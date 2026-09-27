package ssh

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestPersistentCredentialAuthenticatesAfterReopenWithoutAgent(t *testing.T) {
	clearSocksEnv(t)
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "absent"))
	keyPath := writeTempKey(t)
	key, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	signer, err := gssh.ParsePrivateKey(key)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	host, _ := hostSigners(t)
	results := make(chan error, 2)
	go func() {
		for range 2 {
			conn, e := listener.Accept()
			if e != nil {
				results <- e
				return
			}
			cfg := &gssh.ServerConfig{PublicKeyCallback: func(_ gssh.ConnMetadata, key gssh.PublicKey) (*gssh.Permissions, error) {
				if gssh.FingerprintSHA256(key) != gssh.FingerprintSHA256(signer.PublicKey()) {
					return nil, errors.New("wrong identity")
				}
				return nil, nil
			}}
			cfg.AddHostKey(host)
			server, _, _, e := gssh.NewServerConn(conn, cfg)
			results <- e
			if server != nil {
				server.Close()
			}
			conn.Close()
		}
	}()
	store := localstore.New(filepath.Join(t.TempDir(), "config"))
	store.Protector = testutil.NewDeviceProtector()
	target := &config.Server{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, User: "fixture", Auth: config.AuthCloud, CloudEntry: "entry", CloudVault: "owner"}
	require.NoError(t, store.Put(context.Background(), target, []localstore.Credential{{Key: key}}))
	for range 2 {
		fresh := localstore.New(store.ConfigPath)
		fresh.Protector = store.Protector
		client, e := Dial(target, BuildOpts{Insecure: true, ConfigPath: store.ConfigPath, LocalStore: fresh, ProbeOnly: true, Timeout: time.Second})
		require.NoError(t, e)
		client.Close()
		require.NoError(t, <-results)
	}
	// Explicit device lock must dominate even a supplied legacy signer.
	require.NoError(t, store.Lock(context.Background()))
	_, _, err = BuildClientConfig(target, BuildOpts{Insecure: true, LocalStore: store, Signers: []gssh.Signer{signer}})
	require.ErrorContains(t, err, "explicitly locked")
}

func TestManagedAuthRejectsReplacedKeyFile(t *testing.T) {
	path := writeTempKey(t)
	key, err := os.ReadFile(path)
	require.NoError(t, err)
	store := localstore.New(filepath.Join(t.TempDir(), "config"))
	store.Protector = testutil.NewDeviceProtector()
	require.NoError(t, store.RememberKeyFile(context.Background(), path, localstore.Credential{Key: key}))
	target := &config.Server{Host: "fixture", User: "fixture", Auth: config.AuthKey, KeyPath: path}
	require.True(t, HasLocalAuth(target, BuildOpts{LocalStore: store}))
	replacement, err := os.ReadFile(writeTempKey(t))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, replacement, 0600))
	_, _, err = BuildClientConfig(target, BuildOpts{LocalStore: store, Insecure: true})
	require.ErrorContains(t, err, "identity changed")
}

func TestManagedPasswordAndRouteBinding(t *testing.T) {
	store := localstore.New(filepath.Join(t.TempDir(), "config"))
	store.Protector = testutil.NewDeviceProtector()
	target := &config.Server{Host: "fixture", User: "fixture", Auth: config.AuthPassword}
	require.NoError(t, store.Put(context.Background(), target, []localstore.Credential{{Password: []byte("fixture-password")}}))
	target.Proxy = "127.0.0.1:1234"
	require.True(t, HasLocalAuth(target, BuildOpts{LocalStore: store}))
	target.User = "other"
	require.False(t, HasLocalAuth(target, BuildOpts{LocalStore: store}))
}
