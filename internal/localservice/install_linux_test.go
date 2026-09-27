//go:build linux

package localservice

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallUsesPrivateUnitAndUserManager(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", home)
	binDir := filepath.Join(home, "bin")
	require.NoError(t, os.Mkdir(binDir, 0700))
	manager := filepath.Join(binDir, "systemctl")
	log := filepath.Join(home, "manager.log")
	require.NoError(t, os.WriteFile(manager, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SSHM_TEST_MANAGER_LOG\"\n"), 0700))
	t.Setenv("PATH", binDir)
	t.Setenv("SSHM_TEST_MANAGER_LOG", log)
	cfg := filepath.Join(home, "config %name.toml")
	binary := filepath.Join(home, "binary %name$")
	require.NoError(t, Install(cfg, binary, false))
	unitPath := startupPath(cfg)
	st, e := os.Stat(unitPath)
	require.NoError(t, e)
	require.Equal(t, os.FileMode(0600), st.Mode().Perm())
	unit, e := os.ReadFile(unitPath)
	require.NoError(t, e)
	require.Contains(t, string(unit), "%%name$$")
	commands, e := os.ReadFile(log)
	require.NoError(t, e)
	require.Equal(t, "--user daemon-reload\n--user enable --now "+filepath.Base(unitPath)+"\n", string(commands))
	require.True(t, Status(cfg).Startup)
}
func TestPrivateServiceFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	path := filepath.Join(dir, "unit")
	require.NoError(t, os.WriteFile(victim, []byte("safe"), 0600))
	require.NoError(t, os.Symlink(victim, path))
	require.Error(t, privateWrite(path, []byte("overwrite")))
	raw, e := os.ReadFile(victim)
	require.NoError(t, e)
	require.Equal(t, "safe", string(raw))
}
