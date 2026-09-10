package keys

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadPassphraseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("passphrase-file support fails closed on Windows")
	}
	for _, tc := range []struct {
		name, body, want string
		fail             bool
	}{
		{"private", "a user managed secret\n", "a user managed secret", false},
		{"windows newline", "a user managed secret\r\n", "a user managed secret", false},
		{"preserve spaces", " secret spaces ", " secret spaces ", false},
		{"empty", "\n", "", true},
		{"multiline", "secret\nsecond", "", true},
		{"oversized", strings.Repeat("x", 1025), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, os.WriteFile(path, []byte(tc.body), 0600))
			got, err := ReadPassphraseFile(path)
			if tc.fail {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

func TestReadPassphraseFileRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadPassphraseFile(dir)
	require.Error(t, err)
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("private secret"), 0600))
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(path, 0644))
		_, err = ReadPassphraseFile(path)
		require.Error(t, err)
		require.NoError(t, os.Chmod(path, 0600))
		link := filepath.Join(dir, "link")
		require.NoError(t, os.Symlink(path, link))
		_, err = ReadPassphraseFile(link)
		require.Error(t, err)
	}
}
