package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestRemoveCleanupServersIsAtomicAndProtectsReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := config.New()
	old := time.Now().Add(-200 * 24 * time.Hour)
	cfg.Servers["idle"] = &config.Server{LastUsed: old}
	cfg.Servers["jump"] = &config.Server{LastUsed: old}
	cfg.Servers["app"] = &config.Server{LastUsed: time.Now(), ProxyJump: "jump"}
	require.NoError(t, config.Save(path, cfg))

	_, backup, err := removeCleanupServers(path, []string{"idle", "jump"}, 90, time.Now())
	require.Error(t, err)
	require.Empty(t, backup)
	loaded, loadErr := config.Load(path)
	require.NoError(t, loadErr)
	require.Contains(t, loaded.Servers, "idle")
	require.Contains(t, loaded.Servers, "jump")

	removed, backup, err := removeCleanupServers(path, []string{"idle"}, 90, time.Now())
	require.NoError(t, err)
	require.Equal(t, []string{"idle"}, removed)
	require.FileExists(t, backup)
}

func TestBackupConfigIsPrivateAndExact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("version = 5\n"), 0o600))
	backup, err := backupConfig(path, time.Date(2026, 8, 29, 1, 2, 3, 4, time.UTC))
	require.NoError(t, err)
	info, err := os.Stat(backup)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	data, err := os.ReadFile(backup)
	require.NoError(t, err)
	require.Equal(t, "version = 5\n", string(data))
}
