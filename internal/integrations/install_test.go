package integrations

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallRefreshRetainsCustomEditsAndOtherFiles(t *testing.T) {
	home := t.TempDir()
	_, e := Install(home, "codex", "1.0.0", false)
	require.NoError(t, e)
	s, e := Inspect(home, "codex")
	require.NoError(t, e)
	require.True(t, s.Managed)
	require.Equal(t, "1.0.0", s.Version)
	extra := filepath.Join(s.Path, "my-notes.txt")
	require.NoError(t, os.WriteFile(extra, []byte("custom note"), 0600))
	_, e = Install(home, "codex", "1.1.0", true)
	require.NoError(t, e)
	b, e := os.ReadFile(extra)
	require.NoError(t, e)
	require.Equal(t, "custom note", string(b))
	file := filepath.Join(s.Path, "SKILL.md")
	require.NoError(t, os.WriteFile(file, []byte("user modified skill"), 0600))
	_, e = Install(home, "codex", "1.2.0", true)
	require.Error(t, e)
	b, _ = os.ReadFile(file)
	require.Equal(t, "user modified skill", string(b))
}
func TestUnmanagedAndPluginInstallationsArePreserved(t *testing.T) {
	home := t.TempDir()
	path, e := Path(home, "claude")
	require.NoError(t, e)
	require.NoError(t, os.MkdirAll(path, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("existing skill"), 0600))
	_, e = Install(home, "claude", "1.0.0", false)
	require.Error(t, e)
	cache := filepath.Join(home, ".codex", "plugins", "cache", "sshm")
	require.NoError(t, os.MkdirAll(cache, 0700))
	message, e := Install(home, "codex", "1.0.0", false)
	require.NoError(t, e)
	require.Contains(t, message, "plugin-managed")
	status, e := Inspect(home, "codex")
	require.NoError(t, e)
	require.False(t, status.Exists)
}
