package localstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	gssh "golang.org/x/crypto/ssh"
)

// KeyFiles are explicit native path selections. Only actual private-file bytes
// (or a proved matching public half) can authorize reuse; a stale .pub sidecar
// is insufficient when a user has replaced an encrypted private file.
func verifyKeyFile(path string, saved Credential) error {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, path[2:])
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("configured key file cannot be read")
	}
	defer clear(data)
	if bytes.Equal(data, saved.Key) {
		return nil
	}
	actual, err := gssh.ParsePrivateKey(data)
	if err != nil && len(saved.Passphrase) > 0 {
		actual, err = gssh.ParsePrivateKeyWithPassphrase(data, saved.Passphrase)
	}
	var public gssh.PublicKey
	if err == nil {
		public = actual.PublicKey()
	} else {
		var missing *gssh.PassphraseMissingError
		if errors.As(err, &missing) {
			public = missing.PublicKey
		}
	}
	if public == nil || gssh.FingerprintSHA256(public) != saved.Fingerprint {
		return errors.New("configured key file identity changed; register the replacement key locally")
	}
	return nil
}

type Credential struct {
	Key         []byte `json:"key,omitempty"`
	Passphrase  []byte `json:"passphrase,omitempty"`
	Password    []byte `json:"password,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func (c Credential) Signer() (gssh.Signer, error) {
	signer, e := gssh.ParsePrivateKey(c.Key)
	var missing *gssh.PassphraseMissingError
	if errors.As(e, &missing) && len(c.Passphrase) > 0 {
		signer, e = gssh.ParsePrivateKeyWithPassphrase(c.Key, c.Passphrase)
	}
	if e != nil {
		return nil, errors.New("stored SSH key cannot be parsed or decrypted")
	}
	if c.Fingerprint != "" && gssh.FingerprintSHA256(signer.PublicKey()) != c.Fingerprint {
		return nil, errors.New("stored SSH key fingerprint mismatch")
	}
	return signer, nil
}
func CloseCredentials(cs []Credential) {
	for _, c := range cs {
		clear(c.Key)
		clear(c.Passphrase)
		clear(c.Password)
	}
}
func cloneCredentials(cs []Credential) []Credential {
	out := make([]Credential, len(cs))
	for i, c := range cs {
		out[i] = Credential{Key: append([]byte(nil), c.Key...), Passphrase: append([]byte(nil), c.Passphrase...), Password: append([]byte(nil), c.Password...), Fingerprint: c.Fingerprint}
	}
	return out
}
func validateCredentials(cs []Credential) error {
	if len(cs) == 0 || len(cs) > 32 {
		return errors.New("connection needs 1-32 credentials")
	}
	for i := range cs {
		c := &cs[i]
		if len(c.Key) > 1<<20 || len(c.Passphrase) > 65536 || len(c.Password) > 65536 {
			return errors.New("credential too large")
		}
		if len(c.Key) > 0 {
			if len(c.Password) > 0 {
				return errors.New("mixed password and key credential")
			}
			signer, e := c.Signer()
			if e != nil {
				return e
			}
			challenge := make([]byte, 32)
			if _, e = rand.Read(challenge); e != nil {
				return e
			}
			signature, e := signer.Sign(rand.Reader, challenge)
			if e != nil || signer.PublicKey().Verify(challenge, signature) != nil {
				return errors.New("SSH key cannot prove its signing identity")
			}
			c.Fingerprint = gssh.FingerprintSHA256(signer.PublicKey())
		} else if len(c.Password) == 0 || len(c.Passphrase) > 0 || c.Fingerprint != "" {
			return errors.New("invalid credential")
		}
	}
	return nil
}

// Identity deliberately excludes display aliases and all network route fields.
// Explicit key/cloud associations remain part of the binding, so editing an
// authentication source never silently selects an old unrelated credential.
func Identity(s *config.Server) (string, error) {
	if s == nil || strings.TrimSpace(s.Host) == "" || strings.TrimSpace(s.User) == "" {
		return "", errors.New("credential target requires host and user")
	}
	port := s.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return "", errors.New("invalid credential target port")
	}
	vault := s.CloudVault
	if s.CloudEntry == "" && s.Auth != config.AuthCloud {
		// PublishInventory attaches CloudVault as sync metadata to native
		// records. It does not change their explicitly selected local source.
		vault = ""
	}
	data, _ := json.Marshal(struct {
		Host, User, Auth, Key, Entry, Vault string
		Port                                int
	}{s.Host, s.User, s.Auth, s.KeyPath, s.CloudEntry, vault, port})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func keyFileID(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		path = filepath.Join(home, path[2:])
	}
	if path == "" {
		return "", ErrNotFound
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256([]byte(abs))
	return "keyfile/" + hex.EncodeToString(sum[:]), nil
}
