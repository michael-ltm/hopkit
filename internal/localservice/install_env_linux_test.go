//go:build linux

package localservice

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func syntheticUserRuntime(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Match /run/user/<uid> even when the test runner has a permissive umask.
	require.NoError(t, os.Chmod(dir, 0700))
	// Only metadata is needed: no listener or real session manager is started.
	require.NoError(t, syscall.Mknod(filepath.Join(dir, "bus"), syscall.S_IFSOCK|0666, 0))
	return dir
}

func TestUserManagerEnvironmentDerivesMissingSession(t *testing.T) {
	dir := syntheticUserRuntime(t)
	for _, env := range [][]string{
		{"PATH=/synthetic/bin", "HOME=/synthetic/home"},
		{"PATH=/synthetic/bin", "HOME=/synthetic/home", "XDG_RUNTIME_DIR=", "DBUS_SESSION_BUS_ADDRESS="},
	} {
		got, err := userManagerEnvironment(env, dir, uint32(os.Getuid()))
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"PATH=/synthetic/bin", "HOME=/synthetic/home", "XDG_RUNTIME_DIR=" + dir, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + dir + "/bus"}, got)
	}
}

func TestUserManagerEnvironmentPreservesExplicitSession(t *testing.T) {
	for _, env := range [][]string{
		{"PATH=/synthetic/bin", "XDG_RUNTIME_DIR=/explicit/runtime"},
		{"PATH=/synthetic/bin", "DBUS_SESSION_BUS_ADDRESS=unix:path=/explicit/bus"},
		{"XDG_RUNTIME_DIR=/explicit/runtime", "DBUS_SESSION_BUS_ADDRESS=unix:path=/different/bus"},
	} {
		got, err := userManagerEnvironment(env, "/nonexistent/derived/runtime", uint32(os.Getuid()))
		require.NoError(t, err)
		require.Equal(t, env, got)
	}
}

func TestUserManagerEnvironmentRejectsUnsafeDerivedSession(t *testing.T) {
	for _, name := range []string{"directory-symlink", "wrong-owner", "public-directory", "missing-directory", "missing-bus", "regular-bus-file", "bus-symlink"} {
		t.Run(name, func(t *testing.T) {
			dir := syntheticUserRuntime(t)
			uid := uint32(os.Getuid())
			switch name {
			case "directory-symlink":
				link := filepath.Join(t.TempDir(), "runtime")
				require.NoError(t, os.Symlink(dir, link))
				dir = link
			case "wrong-owner":
				uid++
			case "public-directory":
				require.NoError(t, os.Chmod(dir, 0755))
			case "missing-directory":
				dir = filepath.Join(dir, "missing")
			case "missing-bus":
				require.NoError(t, os.Remove(filepath.Join(dir, "bus")))
			case "regular-bus-file":
				require.NoError(t, os.Remove(filepath.Join(dir, "bus")))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "bus"), []byte("synthetic"), 0600))
			case "bus-symlink":
				require.NoError(t, os.Rename(filepath.Join(dir, "bus"), filepath.Join(dir, "real-bus")))
				require.NoError(t, os.Symlink(filepath.Join(dir, "real-bus"), filepath.Join(dir, "bus")))
			}
			got, err := userManagerEnvironment([]string{"PATH=/synthetic/bin"}, dir, uid)
			require.Error(t, err, "must not use unsafe derived session for uid "+strconv.FormatUint(uint64(uid), 10))
			require.Empty(t, got)
		})
	}
}

func TestInstallPassesDerivedSessionToEachManagerCommand(t *testing.T) {
	home := t.TempDir()
	dir := syntheticUserRuntime(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("SSHM_TEST_RUNTIME", dir)
	log := filepath.Join(home, "manager.log")
	t.Setenv("SSHM_TEST_MANAGER_LOG", log)
	old := startupCommandEnvironment
	t.Cleanup(func() { startupCommandEnvironment = old })
	startupCommandEnvironment = func() ([]string, error) {
		return userManagerEnvironment(os.Environ(), dir, uint32(os.Getuid()))
	}
	bin := filepath.Join(home, "bin")
	require.NoError(t, os.Mkdir(bin, 0700))
	t.Setenv("PATH", bin)
	script := "#!/bin/sh\n" +
		"test \"$XDG_RUNTIME_DIR\" = \"$SSHM_TEST_RUNTIME\" || exit 13\n" +
		"test \"$DBUS_SESSION_BUS_ADDRESS\" = \"unix:path=$SSHM_TEST_RUNTIME/bus\" || exit 14\n" +
		"printf '%s\\n' \"$*\" >> \"$SSHM_TEST_MANAGER_LOG\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0700))
	cfg := filepath.Join(home, "config.toml")
	require.NoError(t, Install(cfg, filepath.Join(bin, "sshm"), false))
	commands, err := os.ReadFile(log)
	require.NoError(t, err)
	require.Equal(t, "--user daemon-reload\n--user enable --now "+filepath.Base(startupPath(cfg))+"\n", string(commands))
	require.Empty(t, os.Getenv("XDG_RUNTIME_DIR"), "only the subprocess environment may change")
	require.Empty(t, os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
}
