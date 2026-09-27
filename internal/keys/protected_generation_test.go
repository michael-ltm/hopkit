package keys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestProtectedGenerationPersistsBeforeWritingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	_, err := GenerateED25519Protected(path, "fixture", "random-fixture-pass", func(b []byte) error {
		require.NoFileExists(t, path)
		_, err := gssh.ParsePrivateKeyWithPassphrase(b, []byte("random-fixture-pass"))
		require.NoError(t, err)
		return errors.New("durable protection failed")
	})
	require.ErrorContains(t, err, "durable protection failed")
	require.NoFileExists(t, path)
	require.NoFileExists(t, path+".pub")
	var saved []byte
	_, err = GenerateED25519Protected(path, "fixture", "random-fixture-pass", func(b []byte) error { saved = append([]byte(nil), b...); return nil })
	require.NoError(t, err)
	file, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, saved, file)
}
