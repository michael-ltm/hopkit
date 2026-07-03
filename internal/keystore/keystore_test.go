//go:build !windows

package keystore

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAgentAdd_LoadsDecryptedIdentity(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pass123")
	require.NoError(t, err)

	kr := agent.NewKeyring()
	// os.MkdirTemp (not t.TempDir) keeps the socket path under macOS's
	// 104-byte sun_path limit.
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

	require.NoError(t, agentAdd(keyPath, "pass123"))

	keysInAgent, err := kr.List()
	require.NoError(t, err)
	require.Len(t, keysInAgent, 1)

	want, err := gssh.ParsePrivateKeyWithPassphrase(mustRead(t, keyPath), []byte("pass123"))
	require.NoError(t, err)
	require.Equal(t, want.PublicKey().Marshal(), keysInAgent[0].Blob)
}

func TestAgentAdd_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "right")
	require.NoError(t, err)
	require.Error(t, agentAdd(keyPath, "wrong"))
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}
