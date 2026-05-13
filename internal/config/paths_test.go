package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigDir_UsesXDGOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	got := ConfigDir()
	require.Equal(t, filepath.Join(tmp, "sshm"), got)
}

func TestConfigDir_FallsBackToHomeConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	got := ConfigDir()
	require.Equal(t, filepath.Join(home, ".config", "sshm"), got)
}

func TestConfigDir_UsesAppDataOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)

	got := ConfigDir()
	require.Equal(t, filepath.Join(tmp, "sshm"), got)
}

func TestConfigPath_AppendsConfigTomlToConfigDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	require.Equal(t, filepath.Join(tmp, "sshm", "config.toml"), ConfigPath())
}

func TestAuditPath_AppendsAuditLogToConfigDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	require.Equal(t, filepath.Join(tmp, "sshm", "audit.log"), AuditPath())
}
