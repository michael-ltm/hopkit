// Package localstore is the authoritative, device-protected local credential
// store. Cloud synchronization and SSH Agent lifetimes do not govern access.
package localstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/devicekey"
)

var (
	ErrNotFound       = errors.New("local credential is not configured")
	ErrInactive       = errors.New("local credential was disabled by an accepted deletion; register an active credential locally")
	ErrLocked         = errors.New("device is explicitly locked; run 'sshm service unlock' in a local terminal")
	ErrCorrupt        = errors.New("local credential store failed verification; preserve it and restore its encrypted backup")
	ErrKeyFileChanged = errors.New("configured key file identity changed; register the replacement key locally")
)

const maxStoreSize = 32 << 20

type Store struct {
	ConfigPath string
	Protector  devicekey.Protector
}
type Data struct {
	Version     int                     `json:"version"`
	Connections map[string][]Credential `json:"connections"`
	Secrets     map[string][]byte       `json:"secrets"`
	KeyFiles    map[string]Credential   `json:"key_files"`
	Disabled    map[string]bool         `json:"disabled,omitempty"`
}

func (d *Data) Close() {
	for _, cs := range d.Connections {
		CloseCredentials(cs)
	}
	for _, b := range d.Secrets {
		clear(b)
	}
	for _, c := range d.KeyFiles {
		CloseCredentials([]Credential{c})
	}
}

type envelope struct {
	Version    int    `json:"version"`
	Instance   string `json:"instance"`
	Backend    string `json:"backend"`
	WrappedKey []byte `json:"wrapped_key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func New(path string) *Store {
	if path == "" {
		path = config.ConfigPath()
	}
	abs, e := filepath.Abs(path)
	if e == nil {
		path = abs
	}
	return &Store{ConfigPath: filepath.Clean(path), Protector: devicekey.System{}}
}
func (s *Store) Path() string { return s.ConfigPath + ".local/credentials.json" }
func (s *Store) instance() string {
	sum := sha256.Sum256([]byte(s.ConfigPath))
	return "sshm-" + hex.EncodeToString(sum[:])
}
func (s *Store) Enabled() bool { _, e := os.Lstat(s.Path()); return e == nil || !os.IsNotExist(e) }
func (s *Store) CheckLocked() error {
	_, e := os.Lstat(s.Path() + ".locked")
	if e == nil {
		return ErrLocked
	}
	if !os.IsNotExist(e) {
		return e
	}
	return nil
}
func (s *Store) read(ctx context.Context, allowLocked bool) (*Data, envelope, []byte, error) {
	var enc envelope
	if !allowLocked {
		if e := s.CheckLocked(); e != nil {
			return nil, enc, nil, e
		}
	}
	b, e := readPrivate(s.Path(), maxStoreSize)
	if os.IsNotExist(e) {
		return nil, enc, nil, ErrNotFound
	}
	if e != nil {
		return nil, enc, nil, e
	}
	defer clear(b)
	if json.Unmarshal(b, &enc) != nil || enc.Version != 1 || enc.Instance != s.instance() || len(enc.WrappedKey) > 1<<20 || len(enc.WrappedKey) == 0 {
		return nil, enc, nil, ErrCorrupt
	}
	key, e := s.Protector.Open(ctx, s.instance(), enc.Backend, enc.WrappedKey)
	if e != nil {
		return nil, enc, nil, fmt.Errorf("open device protection: %w", e)
	}
	success := false
	defer func() {
		if !success {
			clear(key)
		}
	}()
	if len(key) != 32 {
		return nil, enc, nil, ErrCorrupt
	}
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	if len(enc.Nonce) != a.NonceSize() {
		return nil, enc, nil, ErrCorrupt
	}
	plain, e := a.Open(nil, enc.Nonce, enc.Ciphertext, []byte(s.instance()+"/data/v1"))
	if e != nil {
		return nil, enc, nil, ErrCorrupt
	}
	defer clear(plain)
	d := &Data{}
	if json.Unmarshal(plain, d) != nil || d.Version != 1 || d.Connections == nil || d.Secrets == nil || d.KeyFiles == nil {
		d.Close()
		return nil, enc, nil, ErrCorrupt
	}
	success = true
	return d, enc, key, nil
}
func (s *Store) Read(ctx context.Context) (*Data, error) {
	if _, e := os.Lstat(s.Path()); os.IsNotExist(e) {
		return nil, ErrNotFound
	} else if e != nil {
		return nil, e
	}
	release, e := lockFile(ctx, s.Path()+".lock")
	if e != nil {
		return nil, e
	}
	defer release()
	d, _, key, e := s.read(ctx, false)
	clear(key)
	return d, e
}
func (s *Store) Update(ctx context.Context, fn func(*Data) error) error {
	if e := prepareDir(filepath.Dir(s.Path())); e != nil {
		return e
	}
	release, e := lockFile(ctx, s.Path()+".lock")
	if e != nil {
		return e
	}
	defer release()
	d, enc, key, e := s.read(ctx, false)
	if errors.Is(e, ErrNotFound) {
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return e
		}
		defer clear(key)
		backend, wrapped, e := s.Protector.Seal(ctx, s.instance(), key)
		if e != nil {
			return e
		}
		// Verify durable device recovery before accepting any credential bytes.
		reopened, e := s.Protector.Open(ctx, s.instance(), backend, wrapped)
		if e != nil {
			return e
		}
		same := len(reopened) == len(key)
		if same {
			for i := range key {
				same = same && key[i] == reopened[i]
			}
		}
		clear(reopened)
		if !same {
			return ErrCorrupt
		}
		enc = envelope{Version: 1, Instance: s.instance(), Backend: backend, WrappedKey: wrapped}
		d = &Data{Version: 1, Connections: map[string][]Credential{}, Secrets: map[string][]byte{}, KeyFiles: map[string]Credential{}}
	} else if e != nil {
		return e
	}
	defer clear(key)
	defer d.Close()
	if e = fn(d); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	plain, e := json.Marshal(d)
	if e != nil {
		return e
	}
	defer clear(plain)
	if len(plain) > maxStoreSize/2 {
		return errors.New("local credential store too large")
	}
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	enc.Nonce = make([]byte, a.NonceSize())
	if _, e = rand.Read(enc.Nonce); e != nil {
		return e
	}
	enc.Ciphertext = a.Seal(nil, enc.Nonce, plain, []byte(s.instance()+"/data/v1"))
	out, e := json.Marshal(enc)
	if e != nil {
		return e
	}
	defer clear(out)
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = s.CheckLocked(); e != nil {
		return e
	}
	return writePrivate(s.Path(), out)
}
func (s *Store) Ensure(ctx context.Context) error {
	if s.Enabled() {
		d, e := s.Read(ctx)
		if d != nil {
			d.Close()
		}
		return e
	}
	return s.Update(ctx, func(*Data) error { return nil })
}
func (s *Store) Put(ctx context.Context, target *config.Server, credentials []Credential) error {
	id, cs, e := prepareCredentials(target, credentials)
	if e != nil {
		return e
	}
	defer CloseCredentials(cs)
	return s.Update(ctx, func(d *Data) error {
		d.put(id, cs)
		return nil
	})
}

// Put validates and stages credentials in an Update transaction. Only a
// successful Update persists them; the transaction owns its own byte copies.
func (d *Data) Put(target *config.Server, credentials []Credential) error {
	id, cs, e := prepareCredentials(target, credentials)
	if e != nil {
		return e
	}
	defer CloseCredentials(cs)
	d.put(id, cs)
	return nil
}
func prepareCredentials(target *config.Server, credentials []Credential) (string, []Credential, error) {
	id, e := Identity(target)
	if e != nil {
		return "", nil, e
	}
	cs := cloneCredentials(credentials)
	if e = validateCredentials(cs); e != nil {
		CloseCredentials(cs)
		return "", nil, e
	}
	return id, cs, nil
}
func (d *Data) put(id string, cs []Credential) {
	CloseCredentials(d.Connections[id])
	d.Connections[id] = cloneCredentials(cs)
	delete(d.Disabled, id)
}
func (s *Store) Resolve(ctx context.Context, target *config.Server) ([]Credential, error) {
	id, e := Identity(target)
	if e != nil {
		return nil, e
	}
	d, e := s.Read(ctx)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	return d.resolve(id, target)
}

// Resolve applies the same target and key-file checks to an already opened
// snapshot, without reopening the device protector for each target.
func (d *Data) Resolve(target *config.Server) ([]Credential, error) {
	id, e := Identity(target)
	if e != nil {
		return nil, e
	}
	return d.resolve(id, target)
}
func (d *Data) resolve(id string, target *config.Server) ([]Credential, error) {
	if d.Disabled[id] {
		return nil, ErrInactive
	}
	cs := d.Connections[id]
	if len(cs) == 0 && target.Auth == config.AuthKey && target.KeyPath != "" {
		if id, e := keyFileID(target.KeyPath); e == nil {
			if c, ok := d.KeyFiles[id]; ok {
				cs = []Credential{c}
			}
		}
	}
	if len(cs) == 0 {
		return nil, ErrNotFound
	}
	if target.Auth == config.AuthKey && target.KeyPath != "" {
		for _, c := range cs {
			if len(c.Key) > 0 {
				if e := verifyKeyFile(target.KeyPath, c); e != nil {
					return nil, e
				}
			}
		}
	}
	return cloneCredentials(cs), nil
}

// Disable retains encrypted recovery material but prevents authentication and
// fallback to an older Agent identity for an accepted cloud deletion.
func (s *Store) Disable(ctx context.Context, target *config.Server) error {
	id, e := Identity(target)
	if e != nil {
		return e
	}
	return s.Update(ctx, func(d *Data) error {
		d.disable(id)
		return nil
	})
}

// Disable stages an accepted deletion while retaining recovery material.
func (d *Data) Disable(target *config.Server) error {
	id, e := Identity(target)
	if e != nil {
		return e
	}
	d.disable(id)
	return nil
}
func (d *Data) disable(id string) {
	if d.Disabled == nil {
		d.Disabled = map[string]bool{}
	}
	d.Disabled[id] = true
}
func (s *Store) RememberKeyFile(ctx context.Context, path string, c Credential) error {
	id, e := keyFileID(path)
	if e != nil {
		return e
	}
	cs := cloneCredentials([]Credential{c})
	defer CloseCredentials(cs)
	if e = validateCredentials(cs); e != nil {
		return e
	}
	return s.Update(ctx, func(d *Data) error {
		if old, ok := d.KeyFiles[id]; ok {
			CloseCredentials([]Credential{old})
		}
		d.KeyFiles[id] = cloneCredentials(cs)[0]
		return nil
	})
}
func (s *Store) KeyFile(ctx context.Context, path string) (Credential, error) {
	id, e := keyFileID(path)
	if e != nil {
		return Credential{}, e
	}
	d, e := s.Read(ctx)
	if e != nil {
		return Credential{}, e
	}
	defer d.Close()
	c, ok := d.KeyFiles[id]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return cloneCredentials([]Credential{c})[0], nil
}
func (s *Store) SetSecret(ctx context.Context, name string, value []byte) error {
	if name == "" || len(name) > 256 || len(value) > 1<<20 {
		return errors.New("invalid local secret")
	}
	return s.Update(ctx, func(d *Data) error {
		return d.SetSecret(name, value)
	})
}

// SetSecret stages a private copy of a secret in the current transaction.
func (d *Data) SetSecret(name string, value []byte) error {
	if name == "" || len(name) > 256 || len(value) > 1<<20 {
		return errors.New("invalid local secret")
	}
	clear(d.Secrets[name])
	d.Secrets[name] = append([]byte(nil), value...)
	return nil
}
func (s *Store) Secret(ctx context.Context, name string) ([]byte, error) {
	d, e := s.Read(ctx)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	b, ok := d.Secrets[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), b...), nil
}
func (s *Store) DeleteSecrets(ctx context.Context, prefix string) error {
	if !s.Enabled() {
		return nil
	}
	return s.Update(ctx, func(d *Data) error {
		for k, b := range d.Secrets {
			if strings.HasPrefix(k, prefix) {
				clear(b)
				delete(d.Secrets, k)
			}
		}
		return nil
	})
}
func (s *Store) Lock(ctx context.Context) error {
	if !s.Enabled() {
		return ErrNotFound
	}
	release, e := lockFile(ctx, s.Path()+".lock")
	if e != nil {
		return e
	}
	defer release()
	return writePrivate(s.Path()+".locked", []byte("explicit device lock\n"))
}
func (s *Store) Unlock(ctx context.Context) error {
	release, e := lockFile(ctx, s.Path()+".lock")
	if e != nil {
		return e
	}
	defer release()
	d, _, key, e := s.read(ctx, true)
	clear(key)
	if d != nil {
		d.Close()
	}
	if e != nil {
		return e
	}
	e = os.Remove(s.Path() + ".locked")
	if os.IsNotExist(e) {
		return nil
	}
	return e
}
