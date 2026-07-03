//go:build darwin

package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/stretchr/testify/require"
)

func TestStoreAndLoad_Darwin_UsesAppleKeychain(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pw")
	require.NoError(t, err)

	var gotArgs []string
	var gotPass string
	orig := runSSHAdd
	t.Cleanup(func() { runSSHAdd = orig })
	runSSHAdd = func(passphrase string, args ...string) error {
		gotArgs = args
		gotPass = passphrase
		return nil
	}

	res, err := StoreAndLoad(keyPath, "pw")
	require.NoError(t, err)
	require.True(t, res.Persisted)
	require.Contains(t, gotArgs, "--apple-use-keychain")
	require.Contains(t, gotArgs, keyPath)
	require.Equal(t, "pw", gotPass)
}

func TestStoreAndLoad_Darwin_FallsBackToSessionAgent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pw")
	require.NoError(t, err)

	orig := runSSHAdd
	t.Cleanup(func() { runSSHAdd = orig })
	runSSHAdd = func(passphrase string, args ...string) error {
		return errors.New("keychain unavailable: no security session")
	}
	// No agent socket set → agentAdd also fails, but StoreAndLoad must
	// surface a non-persistent Result path, not panic. Point at a dead socket.
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "nope.sock"))

	res, err := StoreAndLoad(keyPath, "pw")
	// Either an error (agent unreachable) or a non-persistent result is
	// acceptable; what matters is Persisted is not falsely true.
	if err == nil {
		require.False(t, res.Persisted)
		require.NotEmpty(t, res.Note)
	}
	_ = os.Getpid
}
