//go:build !windows

package localservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func fixture(t *testing.T, rsaKey bool) (*localstore.Store, ssh.PublicKey) {
	t.Helper()
	s := localstore.New(filepath.Join(t.TempDir(), "config.toml"))
	s.Protector = testutil.NewDeviceProtector()
	var raw any
	if rsaKey {
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, e)
		raw = k
	} else {
		_, k, e := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, e)
		raw = k
	}
	block, e := ssh.MarshalPrivateKey(raw, "fixture")
	require.NoError(t, e)
	signer, e := ssh.NewSignerFromKey(raw)
	require.NoError(t, e)
	target := &config.Server{Host: "target.invalid", User: "ops", Auth: config.AuthCloud, CloudEntry: "entry"}
	cfg := config.New()
	cfg.Servers["fixture"] = target
	require.NoError(t, config.Save(s.ConfigPath, cfg))
	require.NoError(t, s.Put(context.Background(), target, []localstore.Credential{{Key: pem.EncodeToMemory(block)}}))
	return s, signer.PublicKey()
}
func start(t *testing.T, s *localstore.Store) (agent.ExtendedAgent, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, func(ctx context.Context) { <-ctx.Done() }) }()
	var conn net.Conn
	require.Eventually(t, func() bool { var e error; conn, e = net.Dial("unix", SocketPath(s.ConfigPath)); return e == nil }, time.Second, 10*time.Millisecond)
	return agent.NewClient(conn), func() { cancel(); require.NoError(t, <-done); _ = conn.Close() }
}
func TestAgentPersistentRestartLockAndImmutableProtocol(t *testing.T) {
	s, key := fixture(t, false)
	client, stop := start(t, s)
	challenge := []byte("challenge")
	sig, e := client.Sign(key, challenge)
	require.NoError(t, e)
	require.NoError(t, key.Verify(challenge, sig))
	require.Error(t, client.RemoveAll())
	require.Error(t, client.Unlock([]byte("ignored")))
	require.Error(t, client.Lock([]byte("ignored")))
	require.Error(t, client.Add(agent.AddedKey{}))
	stop()
	fresh := localstore.New(s.ConfigPath)
	fresh.Protector = s.Protector
	client, stop = start(t, fresh)
	sig, e = client.Sign(key, challenge)
	require.NoError(t, e)
	require.NoError(t, key.Verify(challenge, sig))
	require.NoError(t, s.Lock(context.Background()))
	_, e = client.Sign(key, challenge)
	require.Error(t, e)
	stop()
	client, stop = start(t, fresh)
	defer stop()
	_, e = client.Sign(key, challenge)
	require.Error(t, e)
	require.NoError(t, fresh.Unlock(context.Background()))
	_, e = client.Sign(key, challenge)
	require.NoError(t, e)
	cfg, e := config.Load(s.ConfigPath)
	require.NoError(t, e)
	delete(cfg.Servers, "fixture")
	require.NoError(t, config.Save(s.ConfigPath, cfg))
	_, e = client.Sign(key, challenge)
	require.Error(t, e)
	keys, e := client.List()
	require.NoError(t, e)
	require.Empty(t, keys)

}
func TestConcurrentRunPreservesListenerAndRSAFlags(t *testing.T) {
	s, key := fixture(t, true)
	client, stop := start(t, s)
	defer stop()
	require.ErrorIs(t, Run(context.Background(), s, nil), ErrRunning)
	for _, flag := range []agent.SignatureFlags{agent.SignatureFlagRsaSha256, agent.SignatureFlagRsaSha512} {
		sig, e := client.SignWithFlags(key, []byte("rsa"), flag)
		require.NoError(t, e)
		require.NoError(t, key.Verify([]byte("rsa"), sig))
	}
}

func TestSupervisedRunTakesOverExistingDetachedService(t *testing.T) {
	s, public := fixture(t, false)
	_, stop := start(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, ready := make(chan error, 1), make(chan struct{}, 1)
	go func() { done <- RunSupervised(ctx, s, func(context.Context) { ready <- struct{}{} }) }()
	select {
	case err := <-done:
		t.Fatalf("supervisor should wait: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	stop()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not take over")
	}
	conn, err := net.Dial("unix", SocketPath(s.ConfigPath))
	require.NoError(t, err)
	defer conn.Close()
	sig, err := agent.NewClient(conn).Sign(public, []byte("takeover"))
	require.NoError(t, err)
	require.NoError(t, public.Verify([]byte("takeover"), sig))
	cancel()
	require.NoError(t, <-done)
}
func TestStaleSocketRecoveryAndSymlinkRefusal(t *testing.T) {
	s, _ := fixture(t, false)
	path := SocketPath(s.ConfigPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	ln, e := net.Listen("unix", path)
	require.NoError(t, e)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())
	_, stop := start(t, s)
	stop()
	victim := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(victim, []byte("safe"), 0600))
	require.NoError(t, os.Symlink(victim, path))
	require.Error(t, Run(context.Background(), s, nil))
	b, e := os.ReadFile(victim)
	require.NoError(t, e)
	require.Equal(t, "safe", string(b))
	_ = os.Remove(path)
}
func TestEnsureUnconfiguredIsNoop(t *testing.T) {
	s := localstore.New(filepath.Join(t.TempDir(), "config.toml"))
	require.NoError(t, Ensure(context.Background(), s.ConfigPath))
	require.False(t, Status(s.ConfigPath).Running)
}

func TestBackgroundReturnDoesNotStopAgent(t *testing.T) {
	s, key := fixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	called := make(chan struct{}, 1)
	go func() { done <- Run(ctx, s, func(context.Context) { called <- struct{}{} }) }()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("background did not start")
	}
	conn, e := net.Dial("unix", SocketPath(s.ConfigPath))
	require.NoError(t, e)
	_, e = agent.NewClient(conn).Sign(key, []byte("callback completed"))
	require.NoError(t, e)
	cancel()
	require.NoError(t, <-done)
	_ = conn.Close()
}

func TestInactiveTargetCannotSignWhileOtherTargetCan(t *testing.T) {
	s, key := fixture(t, false)
	cfg, e := config.Load(s.ConfigPath)
	require.NoError(t, e)
	id, e := localstore.Identity(cfg.Servers["fixture"])
	require.NoError(t, e)
	require.NoError(t, s.Update(context.Background(), func(d *localstore.Data) error { d.Disabled = map[string]bool{id: true}; return nil }))
	client, stop := start(t, s)
	defer stop()
	_, e = client.Sign(key, []byte("inactive"))
	require.Error(t, e)
	keys, e := client.List()
	require.NoError(t, e)
	require.Empty(t, keys)
	_, raw, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	block, e := ssh.MarshalPrivateKey(raw, "other")
	require.NoError(t, e)
	otherSigner, e := ssh.NewSignerFromKey(raw)
	require.NoError(t, e)
	other := &config.Server{Host: "other.invalid", User: "ops", Auth: config.AuthCloud, CloudEntry: "other"}
	require.NoError(t, s.Put(context.Background(), other, []localstore.Credential{{Key: pem.EncodeToMemory(block)}}))
	cfg.Servers["other"] = other
	require.NoError(t, config.Save(s.ConfigPath, cfg))
	_, e = client.Sign(otherSigner.PublicKey(), []byte("other active"))
	require.NoError(t, e)
}
