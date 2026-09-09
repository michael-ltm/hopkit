//go:build !windows

package keystore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestStartSessionAgentServesManagedSocketWithoutSSHAgentBinary(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "sshm-session-agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SSH_AUTH_SOCK", sshpkg.ManagedAgentPath())
	t.Setenv("PATH", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, StartSessionAgent(ctx))

	conn, err := sshpkg.DialAgent()
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	keys, err := agent.NewClient(conn).List()
	require.NoError(t, err)
	require.Empty(t, keys)

	stale := sshpkg.ManagedAgentPath()
	require.FileExists(t, stale)
	cancel()
	require.Eventually(t, func() bool {
		_, err := os.Lstat(stale)
		return os.IsNotExist(err)
	}, 2*time.Second, 20*time.Millisecond)
}
