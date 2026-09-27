package keys

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestReadRecoveryPreservesSecretAndStrictPassphraseContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("recovery sidecar ACL validation is unavailable on Windows")
	}
	for _, body := range []string{
		" secret with spaces \n",
		"# sshm recovery — passphrase for fixture\n# move this into your password manager, then delete this file\n secret with spaces \n",
		"# sshm recovery — passphrase for fixture\r\n# move this into your password manager, then delete this file\r\n secret with spaces \r\n",
	} {
		key := filepath.Join(t.TempDir(), "fixture")
		require.NoError(t, os.WriteFile(key+".passphrase", []byte(body), 0600))
		pass, err := ReadRecovery(key)
		require.NoError(t, err)
		require.Equal(t, " secret with spaces ", string(pass))
		clear(pass)
		if strings.HasPrefix(body, "#") {
			_, err = ReadPassphraseFile(key + ".passphrase")
			require.Error(t, err, "explicit passphrase-file remains strictly one line")
		}
	}
}

func TestReadRecoveryPreservesHashPrefixedSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("recovery sidecar ACL validation is unavailable on Windows")
	}
	for _, legacy := range []bool{false, true} {
		key := filepath.Join(t.TempDir(), "fixture")
		if legacy {
			_, err := WriteRecovery(key, "#known-passphrase")
			require.NoError(t, err)
		} else {
			require.NoError(t, os.WriteFile(key+".passphrase", []byte("#known-passphrase\n"), 0600))
		}
		pass, err := ReadRecovery(key)
		require.NoError(t, err)
		require.Equal(t, "#known-passphrase", string(pass))
		clear(pass)
	}
}

func TestReadRecoveryRejectsUnsafeAndAmbiguousFiles(t *testing.T) {
	for _, scenario := range []string{"missing", "directory", "public", "symlink", "empty", "only legacy headers", "unknown comments", "multiple secrets", "trailing comment", "nul", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			key := filepath.Join(t.TempDir(), "fixture")
			path := key + ".passphrase"
			body := "synthetic-secret\n"
			switch scenario {
			case "empty":
				body = "\n"
			case "only legacy headers":
				body = "# sshm recovery — passphrase for fixture\n# move this into your password manager, then delete this file\n"
			case "unknown comments":
				body = "# unknown comment\nsecret\n"
			case "multiple secrets":
				body = "# header\none\ntwo\n"
			case "trailing comment":
				body = "secret\n# comment\n"
			case "nul":
				body = "secret\x00\n"
			case "oversized":
				body = strings.Repeat("# header\n", 130) + "secret\n"
			}
			switch scenario {
			case "missing":
			case "directory":
				require.NoError(t, os.Mkdir(path, 0700))
			case "symlink":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX symlink fixture")
				}
				require.NoError(t, os.WriteFile(key, []byte(body), 0600))
				require.NoError(t, os.Symlink(key, path))
			default:
				require.NoError(t, os.WriteFile(path, []byte(body), 0600))
				if scenario == "public" {
					require.NoError(t, os.Chmod(path, 0644))
				}
			}
			pass, err := ReadRecovery(key)
			require.Error(t, err)
			require.Empty(t, pass)
			require.NotContains(t, err.Error(), "synthetic-secret")
		})
	}
}
