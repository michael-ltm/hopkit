package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestLoadKeySigner_PlainKey(t *testing.T) {
	signer, closer, err := loadKeySigner(writeTempKey(t))
	require.NoError(t, err)
	require.Nil(t, closer, "plain keys need no agent connection")
	require.NotNil(t, signer)
}

func TestLoadKeySigner_EncryptedKeyResolvedViaAgent(t *testing.T) {
	skipIfNoUnixSockets(t)
	priv := genEd25519(t)
	path := writeEncryptedTempKey(t, priv)
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, priv))

	signer, closer, err := loadKeySigner(path)
	require.NoError(t, err)
	require.NotNil(t, closer, "agent connection must be handed to the caller")
	defer closer.Close()

	want, err := gssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	require.Equal(t, want.PublicKey().Marshal(), signer.PublicKey().Marshal())
	_, err = signer.Sign(rand.Reader, []byte("payload"))
	require.NoError(t, err, "agent-backed signer must be able to sign")
}

func TestLoadKeySigner_EncryptedKeyMissingFromAgent(t *testing.T) {
	skipIfNoUnixSockets(t)
	path := writeEncryptedTempKey(t, genEd25519(t))
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, genEd25519(t))) // agent holds a different key

	_, _, err := loadKeySigner(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no matching identity")
}

func TestLoadKeySigner_EncryptedKeyWithoutAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows always has a default agent pipe path")
	}
	path := writeEncryptedTempKey(t, genEd25519(t))
	t.Setenv("SSH_AUTH_SOCK", "")

	_, _, err := loadKeySigner(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "encrypted")
}

func skipIfNoUnixSockets(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("test agent listens on a unix socket")
	}
}

func genEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv
}

// writeEncryptedTempKey writes priv to disk in OpenSSH format, protected by a
// passphrase the test never uses — the key must be resolved via the agent.
func writeEncryptedTempKey(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	block, err := gssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("never-typed"))
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(block), 0o600))
	return p
}

// serveTestAgent runs an in-memory ssh-agent holding priv on a unix socket
// and returns the socket path.
func serveTestAgent(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	kr := agent.NewKeyring()
	require.NoError(t, kr.Add(agent.AddedKey{PrivateKey: priv}))
	return serveAgentBackend(t, kr)
}

func serveAgentBackend(t *testing.T, backend agent.Agent) string {
	t.Helper()
	// os.MkdirTemp, not t.TempDir: the test name would push the socket path
	// past the 104-byte unix socket limit on macOS.
	dir, err := os.MkdirTemp("", "sshm-agent")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(backend, c) }()
		}
	}()
	return sock
}
