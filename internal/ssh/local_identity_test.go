package ssh

import (
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
)

func TestBuildAuthNativeKeyIgnoresCloudBindingMetadata(t *testing.T) {
	path := writeTempKey(t)
	auth, closer, err := buildAuth(&config.Server{
		Auth:       config.AuthKey,
		KeyPath:    path,
		CloudEntry: "entry-1",
		CloudVault: "vault-1",
	}, BuildOpts{})
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
	require.NoError(t, client.Close())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not close")
	}
}

func TestBuildAuthCloudRejectsDifferentRouteOrBinding(t *testing.T) {
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
		func(s *config.Server) { s.ProxyJump = "other-jump" },
		func(s *config.Server) { s.ProxyCommand = "other-command" },
		func(s *config.Server) { s.Proxy = "socks5://127.0.0.1:9999" },
		func(s *config.Server) { s.Forwards = []string{"L:8081:127.0.0.1:80"} },
		func(s *config.Server) { s.CloudEntry = "entry-2" },
		func(s *config.Server) { s.CloudVault = "vault-2" },
	} {
		changed := *server
		changed.Forwards = append([]string(nil), server.Forwards...)
		mutate(&changed)
		_, _, err := buildAuth(&changed, BuildOpts{ConfigPath: configPath})
		require.ErrorContains(t, err, "sshm cloud agent")
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
	require.ErrorContains(t, err, "sshm cloud agent")
	require.NotContains(t, err.Error(), string(gssh.MarshalAuthorizedKey(cachedSigner.PublicKey())))
	require.False(t, HasLocalAuth(server, BuildOpts{ConfigPath: configPath}))
}

func TestHasLocalAuthClosesResolvedSignerResources(t *testing.T) {
	signer, err := gssh.NewSignerFromKey(genEd25519(t))
	require.NoError(t, err)
	closer := &trackingCloser{}
	require.True(t, HasLocalAuth(&config.Server{Auth: config.AuthCloud}, BuildOpts{
		Signers:       []gssh.Signer{signer},
		SignerClosers: []io.Closer{closer},
	}))
	require.True(t, closer.closed)
}

func TestHasLocalAuthNilTargetIsUnavailable(t *testing.T) {
	require.False(t, HasLocalAuth(nil, BuildOpts{}))
}

func TestHasLocalAuthAgentWithSignerIsAvailable(t *testing.T) {
	skipIfNoUnixSockets(t)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, genEd25519(t)))
	require.True(t, HasLocalAuth(&config.Server{Auth: config.AuthAgent}, BuildOpts{}))
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
			require.NoError(t, os.WriteFile(path, []byte(`{"public_keys":["not a public key"]}`), 0o600))
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
