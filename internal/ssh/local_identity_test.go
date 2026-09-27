package ssh

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestBuildAuthNativeKeyIgnoresCloudBindingMetadata(t *testing.T) {
	path := writeTempKey(t)
	auth, closer, err := buildAuth(&config.Server{
		Auth:       config.AuthKey,
		KeyPath:    path,
		CloudEntry: "entry-1",
		CloudVault: "vault-1",
	}, BuildOpts{ConfigPath: filepath.Join(t.TempDir(), "config.toml")})
	require.NoError(t, err)
	require.Len(t, auth, 1)
	require.Nil(t, closer)
}

func TestBuildAuthCloudUsesOnlyCachedAgentIdentityForExactRoute(t *testing.T) {
	skipIfNoUnixSockets(t)
	privateKey := genEd25519(t)
	signer, err := gssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, privateKey))

	configPath := filepath.Join(t.TempDir(), "config.toml")
	server := localIdentityServer()
	require.NoError(t, StoreLocalAgentIdentities(configPath, server, []gssh.PublicKey{signer.PublicKey()}))

	auth, closer, err := buildAuth(server, BuildOpts{ConfigPath: configPath})
	require.NoError(t, err)
	require.Len(t, auth, 1)
	require.NotNil(t, closer)
	require.NoError(t, closer.Close())
}

func TestDialCloudMarkerAuthenticatesWithExactCachedAgentIdentity(t *testing.T) {
	skipIfNoUnixSockets(t)
	clearSocksEnv(t)
	privateKey := genEd25519(t)
	clientSigner, err := gssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, privateKey))
	hostSigner, _ := hostSigners(t)

	var authenticated atomic.Bool
	serverConfig := &gssh.ServerConfig{PublicKeyCallback: func(metadata gssh.ConnMetadata, key gssh.PublicKey) (*gssh.Permissions, error) {
		if metadata.User() != "deploy" || string(key.Marshal()) != string(clientSigner.PublicKey().Marshal()) {
			return nil, errors.New("wrong identity")
		}
		authenticated.Store(true)
		return nil, nil
	}}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		serverConn, channels, requests, serveErr := gssh.NewServerConn(conn, serverConfig)
		if serveErr != nil {
			done <- serveErr
			return
		}
		defer serverConn.Close()
		go gssh.DiscardRequests(requests)
		go func() {
			for channel := range channels {
				_ = channel.Reject(gssh.Prohibited, "fixture")
			}
		}()
		done <- serverConn.Wait()
	}()

	configPath := filepath.Join(t.TempDir(), "config.toml")
	target := &config.Server{
		Host:       "127.0.0.1",
		Port:       listener.Addr().(*net.TCPAddr).Port,
		User:       "deploy",
		Auth:       config.AuthCloud,
		CloudEntry: "entry-1",
		CloudVault: "vault-1",
	}
	require.NoError(t, StoreLocalAgentIdentities(configPath, target, []gssh.PublicKey{clientSigner.PublicKey()}))
	client, err := Dial(target, BuildOpts{ConfigPath: configPath, Insecure: true, Timeout: time.Second})
	require.NoError(t, err)
	require.True(t, authenticated.Load())
	require.Equal(t, "direct", client.Route())
	require.NoError(t, client.Close())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not close")
	}
}

func TestBuildAuthCloudRejectsDifferentTargetOrBinding(t *testing.T) {
	skipIfNoUnixSockets(t)
	privateKey := genEd25519(t)
	signer, err := gssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, privateKey))

	configPath := filepath.Join(t.TempDir(), "config.toml")
	server := localIdentityServer()
	require.NoError(t, StoreLocalAgentIdentities(configPath, server, []gssh.PublicKey{signer.PublicKey()}))

	for _, mutate := range []func(*config.Server){
		func(s *config.Server) { s.Host = "other.invalid" },
		func(s *config.Server) { s.Port++ },
		func(s *config.Server) { s.User = "other" },
		func(s *config.Server) { s.CloudEntry = "entry-2" },
		func(s *config.Server) { s.CloudVault = "vault-2" },
	} {
		changed := *server
		changed.Forwards = append([]string(nil), server.Forwards...)
		mutate(&changed)
		_, _, err := buildAuth(&changed, BuildOpts{ConfigPath: configPath})
		require.ErrorContains(t, err, "sshm service setup")
	}
}

func TestBuildAuthCloudRejectsAgentWithoutCachedIdentity(t *testing.T) {
	skipIfNoUnixSockets(t)
	cachedSigner, err := gssh.NewSignerFromKey(genEd25519(t))
	require.NoError(t, err)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, genEd25519(t)))

	configPath := filepath.Join(t.TempDir(), "config.toml")
	server := localIdentityServer()
	require.NoError(t, StoreLocalAgentIdentities(configPath, server, []gssh.PublicKey{cachedSigner.PublicKey()}))

	_, _, err = buildAuth(server, BuildOpts{ConfigPath: configPath})
	require.Equal(t, "local_identity_unavailable", FailureCategory(err))
	require.NotContains(t, err.Error(), string(gssh.MarshalAuthorizedKey(cachedSigner.PublicKey())))
	require.False(t, HasLocalAuth(server, BuildOpts{ConfigPath: configPath}))
}

func TestHasLocalAuthClosesResolvedSignerResources(t *testing.T) {
	signer, err := gssh.NewSignerFromKey(genEd25519(t))
	require.NoError(t, err)
	closer := &trackingCloser{}
	require.True(t, HasLocalAuth(&config.Server{Auth: config.AuthCloud}, BuildOpts{
		ConfigPath:    filepath.Join(t.TempDir(), "config.toml"),
		Signers:       []gssh.Signer{signer},
		SignerClosers: []io.Closer{closer},
	}))
	require.True(t, closer.closed)
}

func TestHasLocalAuthNilTargetIsUnavailable(t *testing.T) {
	require.False(t, HasLocalAuth(nil, BuildOpts{ConfigPath: filepath.Join(t.TempDir(), "config.toml")}))
}

func TestHasLocalAuthAgentWithSignerIsAvailable(t *testing.T) {
	skipIfNoUnixSockets(t)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, genEd25519(t)))
	require.True(t, HasLocalAuth(&config.Server{Auth: config.AuthAgent}, BuildOpts{ConfigPath: filepath.Join(t.TempDir(), "config.toml")}))
}

func TestStoreLocalAgentIdentitiesUsesPrivatePublicOnlyCache(t *testing.T) {
	privateKey := genEd25519(t)
	signer, err := gssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	configPath := filepath.Join(t.TempDir(), "config.toml")
	server := localIdentityServer()

	require.NoError(t, StoreLocalAgentIdentities(configPath, server, []gssh.PublicKey{signer.PublicKey()}))
	cachePath, err := localIdentityCachePath(configPath, server)
	require.NoError(t, err)
	data, err := os.ReadFile(cachePath)
	require.NoError(t, err)
	require.Contains(t, string(data), strings.TrimSpace(string(gssh.MarshalAuthorizedKey(signer.PublicKey()))))
	require.NotContains(t, string(data), string(privateKey))

	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(filepath.Dir(cachePath))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
		fileInfo, err := os.Stat(cachePath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
	}

	changed := *server
	changed.Auth = config.AuthKey
	changed.KeyPath = "/secret/private-key"
	changedPath, err := localIdentityCachePath(configPath, &changed)
	require.NoError(t, err)
	require.Equal(t, cachePath, changedPath, "auth and key path must not select an identity cache")
}

func TestStoreLocalAgentIdentitiesRejectsUnsafeCacheData(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	server := localIdentityServer()
	validSigner, err := gssh.NewSignerFromKey(genEd25519(t))
	require.NoError(t, err)

	t.Run("malformed public key", func(t *testing.T) {
		err := StoreLocalAgentIdentities(configPath, server, []gssh.PublicKey{malformedPublicKey{}})
		require.ErrorContains(t, err, "invalid public key")
	})

	t.Run("symlink target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation may require privileges on Windows")
		}
		cachePath, err := localIdentityCachePath(configPath, server)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(cachePath), 0o700))
		require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), cachePath))

		err = StoreLocalAgentIdentities(configPath, server, []gssh.PublicKey{validSigner.PublicKey()})
		require.ErrorContains(t, err, "symlink")
	})
}

func TestBuildAuthCloudRejectsMalformedOversizedOrSymlinkCache(t *testing.T) {
	server := localIdentityServer()
	for _, tc := range []struct {
		name    string
		wantErr string
		write   func(*testing.T, string)
	}{
		{name: "malformed", wantErr: "invalid public key", write: func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte(`{"version":2,"public_keys":["not a public key"]}`), 0o600))
		}},
		{name: "oversized", wantErr: "invalid local identity cache file", write: func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, make([]byte, maxLocalIdentityCacheSize+1), 0o600))
		}},
		{name: "symlink", wantErr: "symlink", write: func(t *testing.T, path string) {
			if runtime.GOOS == "windows" {
				t.Skip("symlink creation may require privileges on Windows")
			}
			require.NoError(t, os.WriteFile(path+".target", []byte(`{"public_keys":[]}`), 0o600))
			require.NoError(t, os.Symlink(path+".target", path))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.toml")
			cachePath, err := localIdentityCachePath(configPath, server)
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Dir(cachePath), 0o700))
			tc.write(t, cachePath)

			_, _, err = loadLocalAgentSigners(configPath, server)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestLoadLocalAgentSignersRejectsSymlinkCacheDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require privileges on Windows")
	}
	configPath := filepath.Join(t.TempDir(), "config.toml")
	server := localIdentityServer()
	cachePath, err := localIdentityCachePath(configPath, server)
	require.NoError(t, err)
	realDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(realDir, filepath.Base(cachePath)), []byte(`{"public_keys":[]}`), 0o600))
	require.NoError(t, os.Symlink(realDir, filepath.Dir(cachePath)))

	_, _, err = loadLocalAgentSigners(configPath, server)
	require.ErrorContains(t, err, "symlink")
}

func localIdentityServer() *config.Server {
	return &config.Server{
		Host:         "target.invalid",
		Port:         2022,
		User:         "deploy",
		Auth:         config.AuthCloud,
		CloudEntry:   "entry-1",
		CloudVault:   "vault-1",
		ProxyJump:    "bastion",
		ProxyCommand: "proxy --safe",
		Proxy:        "socks5://127.0.0.1:1080",
		Forwards:     []string{"L:8080:127.0.0.1:80"},
	}
}

type malformedPublicKey struct{}

type trackingCloser struct{ closed bool }

func (c *trackingCloser) Close() error {
	c.closed = true
	return nil
}

func (malformedPublicKey) Type() string { return "ssh-ed25519" }
func (malformedPublicKey) Marshal() []byte {
	return []byte("not-an-ssh-wire-key")
}
func (malformedPublicKey) Verify([]byte, *gssh.Signature) error {
	return errors.New("invalid")
}

func TestLocalIdentitySurvivesRouteChangesAndSigns(t *testing.T) {
	skipIfNoUnixSockets(t)
	raw := genEd25519(t)
	signer, err := gssh.NewSignerFromKey(raw)
	require.NoError(t, err)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, raw))
	path := filepath.Join(t.TempDir(), "config.toml")
	target := localIdentityServer()
	require.NoError(t, StoreLocalAgentIdentities(path, target, []gssh.PublicKey{signer.PublicKey()}))
	target.Proxy = "socks5://127.0.0.1:9999"
	require.True(t, HasLocalAuth(target, BuildOpts{ConfigPath: path}))
	signers, closer, err := loadLocalAgentSigners(path, target)
	require.NoError(t, err)
	defer closer.Close()
	signature, err := signers[0].Sign(nil, []byte("route-independent challenge"))
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify([]byte("route-independent challenge"), signature))
	for _, mutate := range []func(*config.Server){
		func(target *config.Server) { target.ProxyJump = "different-jump" },
		func(target *config.Server) { target.ProxyCommand = "different-command" },
		func(target *config.Server) { target.Forwards = nil },
	} {
		changed := *target
		mutate(&changed)
		require.True(t, HasLocalAuth(&changed, BuildOpts{ConfigPath: path}))
	}
}

func TestCloudLocalIdentityDiagnosticsDoNotRecommendUnlockForInvalidBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	target := localIdentityServer()
	_, _, err := buildAuth(target, BuildOpts{ConfigPath: path})
	require.Equal(t, "local_credential_missing", FailureCategory(err))
	cachePath, err := localIdentityCachePath(path, target)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(cachePath), 0700))
	require.NoError(t, os.WriteFile(cachePath, []byte("invalid json"), 0600))
	_, _, err = buildAuth(target, BuildOpts{ConfigPath: path})
	require.Equal(t, "local_binding_invalid", FailureCategory(err))
	require.NotContains(t, err.Error(), "cloud agent")
}

func TestLegacyIdentityMigrationUsesOnlyExactOrReconstructedDirectTarget(t *testing.T) {
	skipIfNoUnixSockets(t)
	raw := genEd25519(t)
	signer, err := gssh.NewSignerFromKey(raw)
	require.NoError(t, err)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, raw))
	for _, mode := range []string{"exact", "direct", "unrelated-route", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			target := localIdentityServer()
			legacy := *target
			if mode == "direct" {
				legacy.Proxy, legacy.ProxyJump, legacy.ProxyCommand, legacy.Forwards = "", "", "", nil
			}
			if mode == "unrelated-route" {
				legacy.Proxy = "socks5://other:8888"
			}
			if mode == "wrong-target" {
				legacy.User = "root"
			}
			oldPath, err := legacyLocalIdentityCachePath(path, &legacy)
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Dir(oldPath), 0700))
			encoded := strings.TrimSpace(string(gssh.MarshalAuthorizedKey(signer.PublicKey())))
			data, err := json.Marshal(map[string]any{"public_keys": []string{encoded}})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(oldPath, data, 0600))
			require.Equal(t, mode == "exact" || mode == "direct", HasLocalAuth(target, BuildOpts{ConfigPath: path}))
			newPath, err := localIdentityCachePath(path, target)
			require.NoError(t, err)
			if mode == "exact" || mode == "direct" {
				require.FileExists(t, newPath)
			} else {
				require.NoFileExists(t, newPath)
			}
		})
	}
}

func TestCloudLocalIdentityDiagnosticsDistinguishUnavailableAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix Agent socket")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	target := localIdentityServer()
	signer, err := gssh.NewSignerFromKey(genEd25519(t))
	require.NoError(t, err)
	require.NoError(t, StoreLocalAgentIdentities(path, target, []gssh.PublicKey{signer.PublicKey()}))
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing-agent"))
	_, _, err = buildAuth(target, BuildOpts{ConfigPath: path})
	require.Equal(t, "local_agent_unavailable", FailureCategory(err))
	require.NotContains(t, err.Error(), "cloud agent")
}

func TestLegacyMigrationRequiresAgentSigningProof(t *testing.T) {
	skipIfNoUnixSockets(t)
	raw := genEd25519(t)
	signer, err := gssh.NewSignerFromKey(raw)
	require.NoError(t, err)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: raw}))
	t.Setenv("SSH_AUTH_SOCK", serveAgentBackend(t, rejectingSignAgent{Agent: keyring}))
	path := filepath.Join(t.TempDir(), "config.toml")
	target := localIdentityServer()
	oldPath, err := legacyLocalIdentityCachePath(path, target)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(oldPath), 0700))
	data, err := json.Marshal(localIdentityCache{PublicKeys: []string{strings.TrimSpace(string(gssh.MarshalAuthorizedKey(signer.PublicKey())))}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(oldPath, data, 0600))
	require.False(t, HasLocalAuth(target, BuildOpts{ConfigPath: path}))
	newPath, err := localIdentityCachePath(path, target)
	require.NoError(t, err)
	require.NoFileExists(t, newPath)
	require.FileExists(t, oldPath)
}
