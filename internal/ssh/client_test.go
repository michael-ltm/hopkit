package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestReportActivityErrorUsesCallback(t *testing.T) {
	want := errors.New("disk full")
	var got error
	reportActivityError(BuildOpts{ActivityError: func(err error) { got = err }}, want)
	require.ErrorIs(t, got, want)
}

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

func TestBuildClientConfig_CloudEntryDoesNotBlockLocalKey(t *testing.T) {
	keyPath := writeTempKey(t)
	srv := &config.Server{User: "root", Auth: config.AuthKey, KeyPath: keyPath, CloudEntry: "vault-entry"}
	cfg, closer, err := BuildClientConfig(srv, BuildOpts{})
	require.NoError(t, err)
	defer closer.Close()
	require.Len(t, cfg.Auth, 1)
}

func TestBuildClientConfig_AuthCloudUsesLocalKey(t *testing.T) {
	keyPath := writeTempKey(t)
	srv := &config.Server{User: "root", Auth: config.AuthCloud, KeyPath: keyPath}
	cfg, closer, err := BuildClientConfig(srv, BuildOpts{})
	require.NoError(t, err)
	defer closer.Close()
	require.Len(t, cfg.Auth, 1)
}

func TestBuildClientConfig_AuthCloudWithoutMaterialStaysLocked(t *testing.T) {
	srv := &config.Server{User: "root", Auth: config.AuthCloud, CloudEntry: "vault-entry"}
	_, _, err := BuildClientConfig(srv, BuildOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sshm cloud agent")
}

func TestBuildClientConfig_UnavailableLocalKeyRequiresExactCachedVaultIdentity(t *testing.T) {
	skipIfNoUnixSockets(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	local := genEd25519(t)
	vault := genEd25519(t)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, vault))
	encryptedKeyPath := writeEncryptedTempKey(t, local)
	dir := filepath.Join(home, ".ssh", "sshm-keys")
	require.NoError(t, os.MkdirAll(dir, 0700))
	localSigner, err := gssh.NewSignerFromKey(local)
	require.NoError(t, err)
	vaultSigner, err := gssh.NewSignerFromKey(vault)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "prod-7w.pub"), gssh.MarshalAuthorizedKey(localSigner.PublicKey()), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "prod-7w~cde0eb5a.pub"), gssh.MarshalAuthorizedKey(vaultSigner.PublicKey()), 0644))
	// Alias sibling public keys must never authorize an agent identity by
	// themselves; only a cache for this exact route and binding may do so.
	for _, auth := range []string{config.AuthKey, config.AuthCloud} {
		for _, key := range []struct{ name, path string }{
			{"encrypted", encryptedKeyPath},
			{"missing", filepath.Join(home, "missing-key")},
		} {
			for _, cache := range []string{"exact", "absent", "other-route", "other-vault"} {
				t.Run(string(auth)+"/"+key.name+"/"+cache, func(t *testing.T) {
					configPath := filepath.Join(t.TempDir(), "config.toml")
					srv := &config.Server{Host: "prod.invalid", User: "root", Auth: auth, KeyPath: key.path, CloudEntry: "entry-1", CloudVault: "vault-1"}
					cached := *srv
					if cache == "other-route" {
						cached.Host = "other.invalid"
					}
					if cache == "other-vault" {
						cached.CloudVault = "vault-2"
					}
					if cache != "absent" {
						require.NoError(t, StoreLocalAgentIdentities(configPath, &cached, []gssh.PublicKey{vaultSigner.PublicKey()}))
					}
					cfg, closer, err := BuildClientConfig(srv, BuildOpts{Alias: "prod-7w", ConfigPath: configPath, Insecure: true})
					if cache != "exact" {
						require.Error(t, err)
						require.Nil(t, closer)
						return
					}
					require.NoError(t, err)
					defer closer.Close()
					require.Len(t, cfg.Auth, 1)
				})
			}
		}
	}
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
