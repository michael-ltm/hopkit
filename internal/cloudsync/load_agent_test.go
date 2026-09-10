//go:build !windows

package cloudsync

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// This forwards the real Agent protocol to a real keyring; recording constraints
// catches accidentally sending an unconstrained add without waiting 12 hours.
type loadTestAgent struct {
	agent.Agent
	mu   sync.Mutex
	adds []agent.AddedKey
}

func (a *loadTestAgent) Add(key agent.AddedKey) error {
	a.mu.Lock()
	a.adds = append(a.adds, key)
	a.mu.Unlock()
	return a.Agent.Add(key)
}
func startLoadTestAgent(t *testing.T) *loadTestAgent {
	t.Helper()
	dir, err := os.MkdirTemp("", "sshm-load-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	a := &loadTestAgent{Agent: agent.NewKeyring()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(a, c) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return a
}
func loadTestCredential(t *testing.T, pass string) (Credential, ed25519.PrivateKey, gssh.PublicKey) {
	t.Helper()
	_, raw, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var block *pem.Block
	if pass == "" {
		block, err = gssh.MarshalPrivateKey(raw, "fixture")
	} else {
		block, err = gssh.MarshalPrivateKeyWithPassphrase(raw, "fixture", []byte(pass))
	}
	require.NoError(t, err)
	signer, err := gssh.NewSignerFromKey(raw)
	require.NoError(t, err)
	return Credential{Kind: "key", Key: pem.EncodeToMemory(block), Passphrase: []byte(pass), Fingerprint: gssh.FingerprintSHA256(signer.PublicKey())}, raw, signer.PublicKey()
}
func loadTestVault(t *testing.T, credential Credential) (*State, *Vault, *config.Config, string) {
	t.Helper()
	v := &Vault{Master: make([]byte, 32), Envelope: Envelope{Account: "fixture-user"}, Data: NewData()}
	t.Cleanup(v.Close)
	s := &State{URL: "https://fixture.invalid", Username: "fixture-user", Base: Snapshot{RootPublic: v.Public()}}
	e := Entry{ID: "entry-123", Aliases: []string{"same-alias"}, Server: config.Server{Host: "target.invalid", Port: 22, User: "deploy", Auth: config.AuthKey}, CredentialIDs: []string{"credential-123"}}
	credential.Key = append([]byte(nil), credential.Key...)
	credential.Passphrase = append([]byte(nil), credential.Passphrase...)
	v.Data.Credentials["credential-123"] = credential
	v.Data.Entries[e.ID] = e
	target := e.Server
	target.Auth, target.CloudEntry, target.CloudVault = config.AuthCloud, e.ID, InventoryIdentity(s)
	cfg := &config.Config{Servers: map[string]*config.Server{"local-alias": &target}}
	return s, v, cfg, filepath.Join(t.TempDir(), "config.toml")
}

func TestLoadMatchingKeysIntoAgentReusableSigningAndPublicOnlyCache(t *testing.T) {
	a := startLoadTestAgent(t)
	credential, _, public := loadTestCredential(t, "fixture-secret-passphrase")
	s, v, cfg, path := loadTestVault(t, credential)
	before := append([]byte(nil), credential.Key...)
	report, err := LoadMatchingKeysIntoAgent(s, v, cfg, path)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	require.Empty(t, report.Skipped)
	for i := 0; i < 2; i++ {
		conn, err := sshpkg.DialAgent()
		require.NoError(t, err)
		challenge := []byte("independent-client-proof")
		sig, err := agent.NewClient(conn).Sign(public, challenge)
		require.NoError(t, err)
		require.NoError(t, public.Verify(challenge, sig))
		require.NoError(t, conn.Close())
	}
	require.True(t, sshpkg.HasLocalAuth(cfg.Servers["local-alias"], sshpkg.BuildOpts{ConfigPath: path}))
	a.mu.Lock()
	require.Len(t, a.adds, 1)
	require.Equal(t, uint32(43200), a.adds[0].LifetimeSecs)
	a.mu.Unlock()
	require.Equal(t, before, v.Data.Credentials["credential-123"].Key)
	require.Equal(t, []byte("fixture-secret-passphrase"), v.Data.Credentials["credential-123"].Passphrase)
	files := 0
	require.NoError(t, filepath.WalkDir(filepath.Dir(path), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		require.NotContains(t, string(b), "PRIVATE KEY")
		require.NotContains(t, string(b), "fixture-secret-passphrase")
		require.Contains(t, string(b), "ssh-ed25519 ")
		return nil
	}))
	require.Equal(t, 1, files)
}

func TestLoadMatchingKeysIntoAgentRejectsUnsafeSelection(t *testing.T) {
	credential, _, _ := loadTestCredential(t, "")
	for _, test := range []string{"deleted", "conflicted", "wrong-owner", "wrong-account", "wrong-root", "route-host", "route-user", "route-port", "route-jump", "route-command", "route-proxy", "route-forwards", "fingerprint", "alias-only", "ambiguous-route"} {
		t.Run(test, func(t *testing.T) {
			a := startLoadTestAgent(t)
			s, v, cfg, path := loadTestVault(t, credential)
			target := cfg.Servers["local-alias"]
			switch test {
			case "deleted":
				v.Data.Deleted[target.CloudEntry] = true
			case "conflicted":
				v.Data.Conflicts[target.CloudEntry] = Conflict{}
			case "wrong-owner":
				target.CloudVault = "other-owner"
			case "wrong-account":
				s.Username = "different-user"
			case "wrong-root":
				s.Base.RootPublic = "different-root"
			case "route-host":
				target.Host = "different.invalid"
			case "route-user":
				target.User = "root"
			case "route-port":
				target.Port = 2222
			case "route-jump":
				target.ProxyJump = "jump"
			case "route-command":
				target.ProxyCommand = "proxy"
			case "route-proxy":
				target.Proxy = "socks5://different.invalid:1080"
			case "route-forwards":
				target.Forwards = []string{"8080:localhost:80"}
			case "fingerprint":
				c := v.Data.Credentials["credential-123"]
				c.Fingerprint = "SHA256:incorrect"
				v.Data.Credentials["credential-123"] = c
			case "alias-only":
				target.Auth = config.AuthKey
				target.CloudEntry = ""
				target.CloudVault = ""
				target.Host = "different.invalid"
				cfg.Servers = map[string]*config.Server{"same-alias": target}
			case "ambiguous-route":
				target.Auth = config.AuthKey
				target.CloudEntry = ""
				e := v.Data.Entries["entry-123"]
				e.ID = "entry-456"
				v.Data.Entries[e.ID] = e
			}
			report, err := LoadMatchingKeysIntoAgent(s, v, cfg, path)
			if test == "wrong-account" || test == "wrong-root" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Zero(t, report.Loaded)
			identities, err := a.List()
			require.NoError(t, err)
			require.Empty(t, identities)
			require.NoDirExists(t, filepath.Join(filepath.Dir(path), "local-identities"))
		})
	}
}

func TestLoadMatchingKeysIntoAgentDoesNotGuessPassphrases(t *testing.T) {
	a := startLoadTestAgent(t)
	c, _, _ := loadTestCredential(t, "secret-only-in-password-credential")
	c.Passphrase = nil
	s, v, cfg, path := loadTestVault(t, c)
	v.Data.Credentials["password-123"] = Credential{Kind: "password", Password: "secret-only-in-password-credential"}
	e := v.Data.Entries["entry-123"]
	e.CredentialIDs = append(e.CredentialIDs, "password-123")
	v.Data.Entries[e.ID] = e
	report, err := LoadMatchingKeysIntoAgent(s, v, cfg, path)
	require.NoError(t, err)
	require.Zero(t, report.Loaded)
	require.Contains(t, strings.Join(report.Skipped, " "), "passphrase")
	require.NotContains(t, strings.Join(report.Skipped, " "), "secret-only-in-password-credential")
	identities, err := a.List()
	require.NoError(t, err)
	require.Empty(t, identities)
}

func TestLoadMatchingKeysIntoAgentPreservesExistingLifetimeAndNativePaths(t *testing.T) {
	a := startLoadTestAgent(t)
	c, raw, pub := loadTestCredential(t, "")
	_, unrelated, unrelatedPub := loadTestCredential(t, "")
	require.NoError(t, a.Agent.Add(agent.AddedKey{PrivateKey: raw, Comment: "existing", LifetimeSecs: 1}))
	require.NoError(t, a.Agent.Add(agent.AddedKey{PrivateKey: unrelated, Comment: "unrelated"}))
	s, v, cfg, path := loadTestVault(t, c)
	target := cfg.Servers["local-alias"]
	target.Auth, target.CloudEntry, target.KeyPath = config.AuthKey, "", "/native/path/untouched"
	report, err := LoadMatchingKeysIntoAgent(s, v, cfg, path)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	require.Equal(t, "/native/path/untouched", target.KeyPath)
	identities, err := a.List()
	require.NoError(t, err)
	require.Len(t, identities, 2)
	a.mu.Lock()
	require.Empty(t, a.adds)
	a.mu.Unlock()
	require.Eventually(t, func() bool { _, err := a.Sign(pub, []byte("expired")); return err != nil }, 3*time.Second, 20*time.Millisecond)
	sig, err := a.Sign(unrelatedPub, []byte("preserved"))
	require.NoError(t, err)
	require.NoError(t, unrelatedPub.Verify([]byte("preserved"), sig))
}

func TestLoadMatchingKeysIntoAgentNativeAgentUsesUniqueFullRoute(t *testing.T) {
	startLoadTestAgent(t)
	c, _, _ := loadTestCredential(t, "")
	s, v, cfg, path := loadTestVault(t, c)
	target := cfg.Servers["local-alias"]
	target.Auth, target.CloudEntry, target.CloudVault = config.AuthAgent, "", ""
	target.Host, target.Port = "TARGET.invalid", 0
	report, err := LoadMatchingKeysIntoAgent(s, v, cfg, path)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	require.Equal(t, config.AuthAgent, target.Auth)
}
