//go:build linux || windows

package keystore

// Reuses the in-memory agent harness style; on these platforms StoreAndLoad
// loads via the agent. On Windows the OS agent persists; here we only assert
// the key is loaded and no error is returned.
import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestStoreAndLoad_AgentPlatforms(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("windows agent uses a named pipe, not a unix socket")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pw")
	require.NoError(t, err)

	kr := agent.NewKeyring()
	sdir, err := os.MkdirTemp("", "ks-agent")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(sdir) })
	sock := filepath.Join(sdir, "a.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)

	res, err := StoreAndLoad(keyPath, "pw")
	require.NoError(t, err)
	loaded, err := kr.List()
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	_ = res // Persisted/Note are platform-dependent; not asserted here
}

func runtimeIsWindows() bool { return os.PathSeparator == '\\' }
