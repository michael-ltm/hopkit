package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

// We test the ClientConfig builder, which does no I/O against a network.
func TestBuildClientConfig_KeyAuthFromPath(t *testing.T) {
	keyPath := writeTempKey(t)

	srv := &config.Server{User: "ming", Auth: config.AuthKey, KeyPath: keyPath}
	cfg, closer, err := BuildClientConfig(srv, BuildOpts{})
	require.NoError(t, err)
	defer closer.Close()
	require.Equal(t, "ming", cfg.User)
	require.Len(t, cfg.Auth, 1, "exactly one auth method for key auth")
}

func TestBuildClientConfig_RejectsEmptyUser(t *testing.T) {
	srv := &config.Server{Auth: config.AuthKey, KeyPath: writeTempKey(t)}
	_, _, err := BuildClientConfig(srv, BuildOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "user is required")
}

func TestBuildClientConfig_PasswordAuthUsesProvidedPassword(t *testing.T) {
	srv := &config.Server{User: "ming", Auth: config.AuthPassword}
	cfg, closer, err := BuildClientConfig(srv, BuildOpts{Password: "secret"})
	require.NoError(t, err)
	defer closer.Close()
	require.Len(t, cfg.Auth, 1)
}

func TestBuildClientConfig_RejectsMissingKeyFile(t *testing.T) {
	srv := &config.Server{User: "ming", Auth: config.AuthKey, KeyPath: "/no/such/path.pem"}
	_, _, err := BuildClientConfig(srv, BuildOpts{})
	require.Error(t, err)
}

func TestAddress_AppendsDefaultPort(t *testing.T) {
	require.Equal(t, "1.2.3.4:22", Address(&config.Server{Host: "1.2.3.4"}))
	require.Equal(t, "1.2.3.4:2222", Address(&config.Server{Host: "1.2.3.4", Port: 2222}))
}

func TestBuildClientConfig_RejectsPasswordAuthMissingPassword(t *testing.T) {
	srv := &config.Server{User: "ming", Auth: config.AuthPassword}
	_, _, err := BuildClientConfig(srv, BuildOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "password not provided")
}

func TestBuildClientConfig_RejectsUnknownAuth(t *testing.T) {
	srv := &config.Server{User: "ming", Auth: "pubkey-cert"}
	_, _, err := BuildClientConfig(srv, BuildOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported auth")
}

// writeTempKey generates an ed25519 private key on disk for test fixtures.
func writeTempKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gssh.MarshalPrivateKey(priv, "test")
	require.NoError(t, err)
	dir := t.TempDir()
	p := filepath.Join(dir, "id_ed25519")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(block), 0o600))
	return p
}
