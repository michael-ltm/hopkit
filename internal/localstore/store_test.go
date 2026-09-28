package localstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

// The protector is the only fake: storage encryption, file locking, credential
// validation and reopen all execute production code. Its key lives outside the
// copied store, modelling the OS protection boundary.
type testProtector struct{ key []byte }

func TestNativeCredentialSurvivesInventoryAssociation(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "config.toml"))
	s.Protector = testProtector{key: make([]byte, 32)}
	target := &config.Server{Host: "fixture.invalid", User: "ops", Auth: config.AuthPassword}
	require.NoError(t, s.Put(context.Background(), target, []Credential{{Password: []byte("fixture-password")}}))
	target.CloudVault = "associated-vault"
	cs, err := s.Resolve(context.Background(), target)
	require.NoError(t, err)
	CloseCredentials(cs)
	target.CloudVault = "rotated-associated-vault"
	cs, err = s.Resolve(context.Background(), target)
	require.NoError(t, err)
	CloseCredentials(cs)
	target.CloudEntry = "explicit-cloud-source"
	_, err = s.Resolve(context.Background(), target)
	require.ErrorIs(t, err, ErrNotFound)
}

func (p testProtector) Seal(_ context.Context, id string, data []byte) (string, []byte, error) {
	block, _ := aes.NewCipher(p.key)
	a, _ := cipher.NewGCM(block)
	n := make([]byte, a.NonceSize())
	_, _ = rand.Read(n)
	return "test", a.Seal(n, n, data, []byte(id)), nil
}
func (p testProtector) Open(_ context.Context, id, backend string, data []byte) ([]byte, error) {
	if backend != "test" {
		return nil, errors.New("wrong backend")
	}
	block, _ := aes.NewCipher(p.key)
	a, _ := cipher.NewGCM(block)
	if len(data) < a.NonceSize() {
		return nil, errors.New("bad wrapper")
	}
	return a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], []byte(id))
}
func testStore(t *testing.T) *Store {
	t.Helper()
	s := New(filepath.Join(t.TempDir(), "config.toml"))
	s.Protector = testProtector{bytes.Repeat([]byte{1}, 32)}
	return s
}
func testCredential(t *testing.T) Credential {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	b, e := gssh.MarshalPrivateKey(key, "fixture")
	require.NoError(t, e)
	return Credential{Key: pem.EncodeToMemory(b)}
}
func testTarget() *config.Server {
	return &config.Server{Host: "target.invalid", User: "deploy", Port: 22, Auth: config.AuthCloud, CloudEntry: "entry-a", CloudVault: "vault-a"}
}

func TestStoreReopenKeepsIdentityAcrossRouteChanges(t *testing.T) {
	s := testStore(t)
	c := testCredential(t)
	target := testTarget()
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, target, []Credential{c}))
	require.NoError(t, s.SetSecret(ctx, "cloud-token", []byte("fixture-cloud-token")))
	fresh := New(s.ConfigPath)
	fresh.Protector = s.Protector
	target.Proxy = "socks5://127.0.0.1:1080"
	target.Forwards = []string{"8080:127.0.0.1:80"}
	got, e := fresh.Resolve(ctx, target)
	require.NoError(t, e)
	defer CloseCredentials(got)
	require.Len(t, got, 1)
	signer, e := got[0].Signer()
	require.NoError(t, e)
	sig, e := signer.Sign(rand.Reader, []byte("fresh-process"))
	require.NoError(t, e)
	require.NoError(t, signer.PublicKey().Verify([]byte("fresh-process"), sig))
	raw, e := os.ReadFile(s.Path())
	require.NoError(t, e)
	require.NotContains(t, string(raw), "PRIVATE KEY")
	require.NotContains(t, string(raw), "fixture-cloud-token")
	require.NotContains(t, string(raw), "target.invalid")
	changed := *target
	changed.User = "root"
	_, e = fresh.Resolve(ctx, &changed)
	require.ErrorIs(t, e, ErrNotFound)
	changed = *target
	changed.CloudEntry = "entry-b"
	_, e = fresh.Resolve(ctx, &changed)
	require.ErrorIs(t, e, ErrNotFound)
}
func TestStoreRejectsWrongDeviceTamperAndWrongInstance(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, testTarget(), []Credential{testCredential(t)}))
	original, e := os.ReadFile(s.Path())
	require.NoError(t, e)
	other := New(s.ConfigPath)
	other.Protector = testProtector{bytes.Repeat([]byte{2}, 32)}
	_, e = other.Resolve(ctx, testTarget())
	require.Error(t, e)
	require.Error(t, other.SetSecret(ctx, "bad", []byte("no-overwrite")))
	after, _ := os.ReadFile(s.Path())
	require.Equal(t, original, after)
	clone := testStore(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(clone.Path()), 0700))
	require.NoError(t, os.WriteFile(clone.Path(), original, 0600))
	_, e = clone.Resolve(ctx, testTarget())
	require.Error(t, e)
	var enc envelope
	require.NoError(t, json.Unmarshal(original, &enc))
	enc.Ciphertext[len(enc.Ciphertext)-1] ^= 1
	b, _ := json.Marshal(enc)
	require.NoError(t, os.WriteFile(s.Path(), b, 0600))
	_, e = s.Resolve(ctx, testTarget())
	require.Error(t, e)
}
func TestStoreLockPersistsAndCloudLogoutKeepsSSH(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, testTarget(), []Credential{testCredential(t)}))
	require.NoError(t, s.SetSecret(ctx, "cloud/token", []byte("token")))
	require.NoError(t, s.Lock(ctx))
	fresh := New(s.ConfigPath)
	fresh.Protector = s.Protector
	_, e := fresh.Resolve(ctx, testTarget())
	require.ErrorIs(t, e, ErrLocked)
	require.ErrorIs(t, fresh.Ensure(ctx), ErrLocked)
	require.NoError(t, fresh.Unlock(ctx))
	require.NoError(t, fresh.DeleteSecrets(ctx, "cloud/"))
	_, e = fresh.Secret(ctx, "cloud/token")
	require.ErrorIs(t, e, ErrNotFound)
	cs, e := fresh.Resolve(ctx, testTarget())
	require.NoError(t, e)
	CloseCredentials(cs)
}
func TestStoreConcurrentUpdatesDoNotLoseCredentials(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	require.NoError(t, s.Ensure(ctx))
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs <- s.SetSecret(ctx, string(rune('a'+i)), []byte{byte(i)}) }(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	for i := 0; i < 12; i++ {
		b, e := s.Secret(ctx, string(rune('a'+i)))
		require.NoError(t, e)
		require.Equal(t, []byte{byte(i)}, b)
	}
}

func TestStoreUpdateCancellationDoesNotCommitStagedSecrets(t *testing.T) {
	s := testStore(t)
	require.NoError(t, s.SetSecret(context.Background(), "keep", []byte("original")))
	before, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = s.Update(ctx, func(d *Data) error {
		d.Secrets["staged"] = []byte("must not persist")
		cancel()
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
	after, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestStoreUpdateNewLockDoesNotCommitStagedSecrets(t *testing.T) {
	s := testStore(t)
	require.NoError(t, s.SetSecret(context.Background(), "keep", []byte("original")))
	before, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	err = s.Update(context.Background(), func(d *Data) error {
		d.Secrets["staged"] = []byte("must not persist")
		return os.WriteFile(s.Path()+".locked", []byte("explicit device lock\n"), 0600)
	})
	require.ErrorIs(t, err, ErrLocked)
	after, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	require.True(t, bytes.Equal(before, after))
}
func TestStoreValidatesKeyBeforePersisting(t *testing.T) {
	s := testStore(t)
	c := testCredential(t)
	c.Fingerprint = "SHA256:wrong"
	require.Error(t, s.Put(context.Background(), testTarget(), []Credential{c}))
	require.NoFileExists(t, s.Path())
}
func TestStoreRejectsSymlinkDestination(t *testing.T) {
	s := testStore(t)
	victim := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(victim, []byte("original"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(s.Path()), 0700))
	if e := os.Symlink(victim, s.Path()); e != nil {
		t.Skip(e)
	}
	require.Error(t, s.Ensure(context.Background()))
	b, _ := os.ReadFile(victim)
	require.Equal(t, "original", string(b))
}

func TestStoreRejectsKeyThatCannotVerifyItsOwnSignature(t *testing.T) {
	s := testStore(t)
	_, raw, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	raw[0] ^= 1 // seed no longer derives the public half of the key.
	block, e := gssh.MarshalPrivateKey(raw, "broken-fixture")
	require.NoError(t, e)
	require.Error(t, s.Put(context.Background(), testTarget(), []Credential{{Key: pem.EncodeToMemory(block)}}))
	require.NoFileExists(t, s.Path())
}

func TestStoreReadDuringUpdateIsAConsistentSnapshot(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	require.NoError(t, s.SetSecret(ctx, "value", []byte("old")))
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if j%2 == 0 {
					errs <- s.SetSecret(ctx, "value", []byte("new"))
				} else {
					_, e := s.Secret(ctx, "value")
					errs <- e
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
}

func TestStoreReadWaitsForWriterAndHonorsCancellation(t *testing.T) {
	s := testStore(t)
	require.NoError(t, s.Ensure(context.Background()))
	release, e := lockFile(context.Background(), s.Path()+".lock")
	require.NoError(t, e)
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	d, e := s.Read(ctx)
	if d != nil {
		d.Close()
	}
	require.ErrorIs(t, e, context.DeadlineExceeded)
}
