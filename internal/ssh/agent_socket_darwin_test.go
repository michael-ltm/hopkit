//go:build darwin

package ssh

import (
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnAgentSocketRejectsFilesAndSymlinks(t *testing.T) {
	// Darwin's Unix socket path limit is shorter than Go's default temp path.
	dir, err := os.MkdirTemp("/tmp", "sshm-agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer listener.Close()
	require.Equal(t, path, ownAgentSocket(path))
	require.Empty(t, ownAgentSocket(""))
	require.Empty(t, ownAgentSocket(filepath.Join(dir, "missing")))
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, []byte("not a socket"), 0600))
	require.Empty(t, ownAgentSocket(file))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(path, link))
	require.Empty(t, ownAgentSocket(link))
}
