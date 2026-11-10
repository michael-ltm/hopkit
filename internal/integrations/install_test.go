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

// legacyInstall writes a pristine sshm-era managed skill at the old path.
func legacyInstall(t *testing.T, home, app string) string {
	t.Helper()
	dir, e := skillsDir(home, app)
	require.NoError(t, e)
	legacy := filepath.Join(dir, legacySkillName)
	require.NoError(t, os.MkdirAll(legacy, 0700))
	body := []byte("legacy skill")
	require.NoError(t, os.WriteFile(filepath.Join(legacy, "SKILL.md"), body, 0600))
	manifest := `{"owner":"sshm-managed-v1","version":"0.7.1","files":{"SKILL.md":"` + hash(body) + `"}}`
	require.NoError(t, os.WriteFile(filepath.Join(legacy, marker), []byte(manifest), 0600))
	return legacy
}

func TestInstallMovesPristineLegacySkillOutOfSkillsDirectory(t *testing.T) {
	home := t.TempDir()
	legacy := legacyInstall(t, home, "codex")
	message, e := Install(home, "codex", "0.8.0", false)
	require.NoError(t, e)
	require.Contains(t, message, "legacy")
	_, e = os.Stat(legacy)
	require.True(t, os.IsNotExist(e), "legacy skill must leave the skills directory")
	dir, _ := skillsDir(home, "codex")
	entries, e := os.ReadDir(dir)
	require.NoError(t, e)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	require.Equal(t, []string{skillName}, names, "only the hopkit skill may remain loadable")
	backups, e := os.ReadDir(filepath.Join(home, ".agents", "skill-backups"))
	require.NoError(t, e)
	require.Len(t, backups, 1)
}

func TestRefreshMigratesLegacySkill(t *testing.T) {
	home := t.TempDir()
	legacyInstall(t, home, "claude")
	_, e := Install(home, "claude", "0.8.0", true)
	require.NoError(t, e)
	s, e := Inspect(home, "claude")
	require.NoError(t, e)
	require.True(t, s.Managed)
	require.Equal(t, "0.8.0", s.Version)
}

func TestEditedLegacySkillIsRetained(t *testing.T) {
	home := t.TempDir()
	legacy := legacyInstall(t, home, "codex")
	require.NoError(t, os.WriteFile(filepath.Join(legacy, "SKILL.md"), []byte("user edits"), 0600))
	message, e := Install(home, "codex", "0.8.0", false)
	require.NoError(t, e)
	require.Contains(t, message, "retained")
	b, e := os.ReadFile(filepath.Join(legacy, "SKILL.md"))
	require.NoError(t, e)
	require.Equal(t, "user edits", string(b))
}

func TestReinstallBackupStaysOutsideSkillsDirectory(t *testing.T) {
	home := t.TempDir()
	_, e := Install(home, "claude", "0.8.0", false)
	require.NoError(t, e)
	_, e = Install(home, "claude", "0.8.1", true)
	require.NoError(t, e)
	dir, _ := skillsDir(home, "claude")
	entries, e := os.ReadDir(dir)
	require.NoError(t, e)
	require.Len(t, entries, 1)
	backups, e := os.ReadDir(filepath.Join(home, ".claude", "skill-backups"))
	require.NoError(t, e)
	require.Len(t, backups, 1)
}

func TestLegacyPluginCacheStillCountsAsPluginManaged(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".claude", "plugins", "cache", "hopkit"), 0700))
	s, e := Inspect(home, "claude")
	require.NoError(t, e)
	require.True(t, s.Plugin)
}
