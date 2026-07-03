package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteRecovery_WritesModeAndContent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_x")
	rp, err := WriteRecovery(keyPath, "topsecret")
	require.NoError(t, err)
	require.Equal(t, keyPath+".passphrase", rp)

	data, err := os.ReadFile(rp)
	require.NoError(t, err)
	require.Contains(t, string(data), "topsecret")

	if os.PathSeparator == '/' {
		st, err := os.Stat(rp)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}
	require.True(t, strings.Contains(string(data), "id_x"), "header names the key")
}

func TestWriteRecovery_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_x")
	_, err := WriteRecovery(keyPath, "a")
	require.NoError(t, err)
	_, err = WriteRecovery(keyPath, "b")
	require.Error(t, err)
}
