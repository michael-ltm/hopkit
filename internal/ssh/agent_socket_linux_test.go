//go:build linux

package ssh

import (
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestLinuxAgentRecovery(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "sshm-recovery-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SSH_AUTH_SOCK", "")
	legacy := filepath.Join(home, ".ssh", "sshm-agent.sock")
	managed := ManagedAgentPath()
	for _, p := range []string{legacy, managed} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0700))
	}
	key := genEd25519(t)
	keyPath := writeEncryptedTempKey(t, key)
	require.NoError(t, os.Rename(serveTestAgent(t, key), legacy))
	require.NoError(t, os.Rename(serveAgentBackend(t, agent.NewKeyring()), managed))
	t.Run("original agent wins over empty managed agent", func(t *testing.T) {
		signer, closer, err := loadKeySigner(keyPath)
		require.NoError(t, err)
		defer closer.Close()
		sig, err := signer.Sign(rand.Reader, []byte("recovery"))
		require.NoError(t, err)
		require.NoError(t, signer.PublicKey().Verify([]byte("recovery"), sig))
	})
	t.Run("explicit environment stays authoritative", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", managed)
		_, _, err := loadKeySigner(keyPath)
		require.ErrorContains(t, err, "no matching identity")
	})
	replacement := serveAgentBackend(t, agent.NewKeyring())
	require.NoError(t, os.Rename(replacement, legacy))
	require.NoError(t, os.Rename(serveTestAgent(t, key), managed))
	t.Run("empty original agent does not hide managed signing key", func(t *testing.T) {
		signer, closer, err := loadKeySigner(keyPath)
		require.NoError(t, err)
		defer closer.Close()
		_, err = signer.Sign(rand.Reader, []byte("managed recovery"))
		require.NoError(t, err)
	})
	require.NoError(t, os.Remove(legacy))
	dead, err := net.ListenUnix("unix", &net.UnixAddr{Name: legacy, Net: "unix"})
	require.NoError(t, err)
	dead.SetUnlinkOnClose(false)
	require.NoError(t, dead.Close())
	t.Run("stale original socket falls back to managed agent", func(t *testing.T) {
		conn, err := dialAgent()
		require.NoError(t, err)
		defer conn.Close()
		keys, err := agent.NewClient(conn).List()
		require.NoError(t, err)
		require.Len(t, keys, 1)
	})
	require.NoError(t, os.Remove(legacy))
	require.NoError(t, os.Symlink(managed, legacy))
	require.Empty(t, platformAgentSocket(), "do not follow discovered symlinks")
}
