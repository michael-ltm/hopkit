//go:build !windows

package cloudsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestLoadMatchingKeysIntoAgentUsesVaultPassphraseWithoutRewriting(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sshm-load-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))

	socket := filepath.Join(dir, "agent")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("SSH_AUTH_SOCK", socket)
	ring := agent.NewKeyring()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(ring, c) }()
		}
	}()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pass := []byte("vault-held-passphrase")
	block, err := gssh.MarshalPrivateKeyWithPassphrase(private, "sshm protected", pass)
	require.NoError(t, err)
	encrypted := pem.EncodeToMemory(block)
	keyPath := filepath.Join(dir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, encrypted, 0600))

	signer, err := gssh.NewSignerFromKey(private)
	require.NoError(t, err)
	pub := signer.PublicKey()
	require.NoError(t, os.WriteFile(keyPath+".pub", gssh.MarshalAuthorizedKey(pub), 0644))

	v, _, err := NewVault("load-test", []byte("test-unlock"))
	require.NoError(t, err)
	t.Cleanup(v.Close)
	cred := Credential{Kind: "key", Key: append([]byte(nil), encrypted...), Passphrase: append([]byte(nil), pass...), Fingerprint: gssh.FingerprintSHA256(pub)}
	v.Data.Credentials[Digest(cred)] = cred

	cfg := config.New()
	cfg.Servers["prod-go"] = &config.Server{Host: "test.invalid", Port: 22, User: "root", Auth: config.AuthKey, KeyPath: keyPath}

	report, err := LoadMatchingKeysIntoAgent(v, cfg)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)

	after, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, encrypted, after, "local key file must stay encrypted and unchanged")

	challenge := []byte("sshm-restore")
	sig, err := ring.Sign(pub, challenge)
	require.NoError(t, err)
	require.NoError(t, pub.Verify(challenge, sig))
	published, err := os.ReadFile(filepath.Join(dir, ".ssh", "sshm-keys", "prod-go.pub"))
	require.NoError(t, err)
	got, _, _, _, err := gssh.ParseAuthorizedKey(published)
	require.NoError(t, err)
	require.Equal(t, gssh.FingerprintSHA256(pub), gssh.FingerprintSHA256(got))
}

func TestLoadMatchingKeysIntoAgentUsesVaultCopyWhenLocalPassphraseMissing(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sshm-load-copy-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))

	socket := filepath.Join(dir, "agent")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("SSH_AUTH_SOCK", socket)
	ring := agent.NewKeyring()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(ring, c) }()
		}
	}()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	encBlock, err := gssh.MarshalPrivateKeyWithPassphrase(private, "sshm protected", []byte("unknown-local-pass"))
	require.NoError(t, err)
	encrypted := pem.EncodeToMemory(encBlock)
	plainBlock, err := gssh.MarshalPrivateKey(private, "imported")
	require.NoError(t, err)
	plain := pem.EncodeToMemory(plainBlock)
	keyPath := filepath.Join(dir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, encrypted, 0600))

	signer, err := gssh.NewSignerFromKey(private)
	require.NoError(t, err)
	pub := signer.PublicKey()

	v, _, err := NewVault("load-copy", []byte("test-unlock"))
	require.NoError(t, err)
	t.Cleanup(v.Close)
	cred := Credential{Kind: "key", Key: append([]byte(nil), plain...), Fingerprint: gssh.FingerprintSHA256(pub)}
	v.Data.Credentials[Digest(cred)] = cred

	cfg := config.New()
	cfg.Servers["dps-ts"] = &config.Server{Host: "test.invalid", Port: 22, User: "root", Auth: config.AuthKey, KeyPath: keyPath}

	report, err := LoadMatchingKeysIntoAgent(v, cfg)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	after, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.True(t, bytes.Equal(encrypted, after))

	sig, err := ring.Sign(pub, []byte("copy"))
	require.NoError(t, err)
	require.NoError(t, pub.Verify([]byte("copy"), sig))
}

func TestLoadMatchingKeysIntoAgentUsesSidecarPasswordCredential(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sshm-load-sidecar-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))

	socket := filepath.Join(dir, "agent")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("SSH_AUTH_SOCK", socket)
	ring := agent.NewKeyring()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(ring, c) }()
		}
	}()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pass := []byte("sidecar-recovery-phrase")
	block, err := gssh.MarshalPrivateKeyWithPassphrase(private, "sshm protected", pass)
	require.NoError(t, err)
	encrypted := pem.EncodeToMemory(block)
	keyPath := filepath.Join(dir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, encrypted, 0600))
	signer, err := gssh.NewSignerFromKey(private)
	require.NoError(t, err)
	pub := signer.PublicKey()

	v, _, err := NewVault("load-sidecar", []byte("test-unlock"))
	require.NoError(t, err)
	t.Cleanup(v.Close)
	locked := Credential{Kind: "key", Key: append([]byte(nil), encrypted...), Fingerprint: gssh.FingerprintSHA256(pub)}
	v.Data.Credentials[Digest(locked)] = locked
	sidecar := Credential{Kind: "password", Password: string(pass), Fingerprint: "sshm-sidecar-backup:fixture"}
	v.Data.Credentials[Digest(sidecar)] = sidecar

	cfg := config.New()
	cfg.Servers["prod-go"] = &config.Server{Host: "test.invalid", Port: 22, User: "root", Auth: config.AuthKey, KeyPath: keyPath}

	report, err := LoadMatchingKeysIntoAgent(v, cfg)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	sig, err := ring.Sign(pub, []byte("sidecar"))
	require.NoError(t, err)
	require.NoError(t, pub.Verify([]byte("sidecar"), sig))
}
