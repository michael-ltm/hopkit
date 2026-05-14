package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateED25519_WritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_test")
	pub, err := GenerateED25519(path, "test@host")
	require.NoError(t, err)
	require.Contains(t, pub, "ssh-ed25519")
	require.Contains(t, pub, "test@host")

	st, err := os.Stat(path)
	require.NoError(t, err)
	if osIsUnix() {
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	pubData, err := os.ReadFile(path + ".pub")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(pubData), "ssh-ed25519 "))
	require.Contains(t, string(pubData), "test@host", ".pub file should embed comment")

	pubStat, err := os.Stat(path + ".pub")
	require.NoError(t, err)
	if osIsUnix() {
		require.Equal(t, os.FileMode(0o644), pubStat.Mode().Perm())
	}
}

func TestGenerateED25519_RefusesToOverwriteExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_test")
	require.NoError(t, os.WriteFile(path, []byte("existing"), 0o600))

	_, err := GenerateED25519(path, "test@host")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestGenerateED25519_StripsNewlinesFromComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_test")
	pub, err := GenerateED25519(path, "good\nmalicious-extra-line")
	require.NoError(t, err)
	// Only one line — comment-injection prevented.
	require.Equal(t, 1, strings.Count(pub, "\n"))
	// Newline was stripped, so there is no injected second line.
	require.NotContains(t, pub, "\nmalicious-extra-line")
	require.Contains(t, pub, "goodmalicious-extra-line")
}

func osIsUnix() bool { return os.PathSeparator == '/' }
