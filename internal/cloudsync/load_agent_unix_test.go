//go:build !windows

package cloudsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
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

	state, configPath := bindLoadRecoveryEntry(t, v, cfg)
	report, err := LoadMatchingKeysIntoAgent(state, v, cfg, configPath)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)

	after, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, encrypted, after, "local key file must stay encrypted and unchanged")

	challenge := []byte("sshm-restore")
	sig, err := ring.Sign(pub, challenge)
	require.NoError(t, err)
	require.NoError(t, pub.Verify(challenge, sig))
	require.True(t, sshpkg.HasLocalAuth(cfg.Servers["prod-go"], sshpkg.BuildOpts{ConfigPath: configPath}))
	caches, err := filepath.Glob(filepath.Join(filepath.Dir(configPath), "local-identities", "*.json"))
	require.NoError(t, err)
	require.Len(t, caches, 1)
	published, err := os.ReadFile(caches[0])
	require.NoError(t, err)
	var cached struct {
		PublicKeys []string `json:"public_keys"`
	}
	require.NoError(t, json.Unmarshal(published, &cached))
	require.Len(t, cached.PublicKeys, 1)
	got, _, _, _, err := gssh.ParseAuthorizedKey([]byte(cached.PublicKeys[0]))
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

	state, configPath := bindLoadRecoveryEntry(t, v, cfg)
	report, err := LoadMatchingKeysIntoAgent(state, v, cfg, configPath)
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

	state, configPath := bindLoadRecoveryEntry(t, v, cfg)
	report, err := LoadMatchingKeysIntoAgent(state, v, cfg, configPath)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	sig, err := ring.Sign(pub, []byte("sidecar"))
	require.NoError(t, err)
	require.NoError(t, pub.Verify([]byte("sidecar"), sig))
}

// Bind imported fixtures to the same full route as the local alias. Recovery
// material outside this entry must never participate in unlocking that alias.
func bindLoadRecoveryEntry(t *testing.T, v *Vault, cfg *config.Config) (*State, string) {
	t.Helper()
	state := &State{URL: "https://fixture.invalid", Username: v.Envelope.Account, Base: Snapshot{RootPublic: v.Public()}}
	for alias, server := range cfg.Servers {
		entry := Entry{ID: "recovery-entry", Aliases: []string{alias}, Server: cleanServer(*server)}
		for id := range v.Data.Credentials {
			entry.CredentialIDs = append(entry.CredentialIDs, id)
		}
		v.Data.Entries[entry.ID] = entry
	}
	return state, filepath.Join(t.TempDir(), "config.toml")
}

func TestLoadMatchingKeysIntoAgentLocalRecoveryIsScopedToEntry(t *testing.T) {
	for _, test := range []string{"same-entry-sidecar", "unrelated-sidecar", "unreferenced-sidecar", "ordinary-password", "wrong-route", "wrong-owner", "deleted-entry", "conflicted-entry", "wrong-fingerprint", "key-passphrase", "legacy-sidecar", "legacy-wrong-device", "legacy-wrong-path"} {
		t.Run(test, func(t *testing.T) {
			ring := startLoadTestAgent(t)
			credential, _, public := loadTestCredential(t, "local-recovery-pass")
			encrypted := append([]byte(nil), credential.Key...)
			credential.Passphrase = nil
			if test == "key-passphrase" {
				credential.Key = nil
				credential.Passphrase = []byte("local-recovery-pass")
			}
			state, v, cfg, path := loadTestVault(t, credential)
			target := cfg.Servers["local-alias"]
			target.Auth = config.AuthKey
			target.KeyPath = filepath.Join(t.TempDir(), "id_ed25519")
			require.NoError(t, os.WriteFile(target.KeyPath, encrypted, 0600))
			sidecar := Credential{Kind: "password", Password: "local-recovery-pass", Fingerprint: "sshm-sidecar-backup:fixture"}
			if test == "ordinary-password" {
				sidecar.Fingerprint = ""
			}
			state.DeviceID = "fixture-device"
			if test == "legacy-sidecar" || test == "legacy-wrong-device" || test == "legacy-wrong-path" {
				device, keyPath := state.DeviceID, target.KeyPath
				if test == "legacy-wrong-device" {
					device = "other-device"
				}
				if test == "legacy-wrong-path" {
					keyPath += ".other"
				}
				sidecar.Fingerprint = "sshm-sidecar-backup:" + Digest([]string{device, keyPath})
			}
			entry := v.Data.Entries[target.CloudEntry]
			v.Data.Credentials["sidecar-123"] = sidecar
			if test != "unrelated-sidecar" && test != "unreferenced-sidecar" && test != "key-passphrase" && test != "legacy-sidecar" && test != "legacy-wrong-device" && test != "legacy-wrong-path" {
				entry.CredentialIDs = append(entry.CredentialIDs, "sidecar-123")
			}
			v.Data.Entries[entry.ID] = entry
			switch test {
			case "unrelated-sidecar":
				other := entry
				other.ID, other.Server.Host, other.CredentialIDs = "other-entry", "elsewhere.invalid", []string{"sidecar-123"}
				v.Data.Entries[other.ID] = other
			case "wrong-route":
				target.Host = "elsewhere.invalid"
			case "wrong-owner":
				target.CloudVault = "other-owner"
			case "deleted-entry":
				v.Data.Deleted[entry.ID] = true
			case "conflicted-entry":
				v.Data.Conflicts[entry.ID] = Conflict{}
			case "wrong-fingerprint":
				c := v.Data.Credentials["credential-123"]
				c.Fingerprint = "SHA256:incorrect"
				v.Data.Credentials["credential-123"] = c
			}
			report, err := LoadMatchingKeysIntoAgent(state, v, cfg, path)
			require.NoError(t, err)
			if test == "same-entry-sidecar" || test == "key-passphrase" || test == "legacy-sidecar" {
				require.Equal(t, 1, report.Loaded)
				sig, err := ring.Sign(public, []byte("local-recovery"))
				require.NoError(t, err)
				require.NoError(t, public.Verify([]byte("local-recovery"), sig))
				require.True(t, sshpkg.HasLocalAuth(target, sshpkg.BuildOpts{ConfigPath: path}))
			} else {
				require.Zero(t, report.Loaded)
				identities, err := ring.List()
				require.NoError(t, err)
				require.Empty(t, identities)
				require.NoDirExists(t, filepath.Join(filepath.Dir(path), "local-identities"))
			}
			after, err := os.ReadFile(target.KeyPath)
			require.NoError(t, err)
			require.Equal(t, encrypted, after)
			require.NotContains(t, strings.Join(report.Skipped, " "), "local-recovery-pass")
		})
	}
}
