//go:build linux

package localservice

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var startupCommandEnvironment = func() ([]string, error) {
	uid := os.Getuid()
	return userManagerEnvironment(os.Environ(), filepath.Join("/run/user", strconv.Itoa(uid)), uint32(uid))
}

// systemctl accepts either explicit session selector. Respect those settings;
// headless callers with neither may use only the current user's private runtime.
func userManagerEnvironment(env []string, dir string, uid uint32) ([]string, error) {
	for _, item := range env {
		name, value, _ := strings.Cut(item, "=")
		if value != "" && (name == "XDG_RUNTIME_DIR" || name == "DBUS_SESSION_BUS_ADDRESS") {
			return env, nil
		}
	}
	unavailable := errors.New("safe local user service session is unavailable")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, unavailable
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid {
		return nil, unavailable
	}
	bus := filepath.Join(dir, "bus")
	info, err = os.Lstat(bus)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return nil, unavailable
	}
	owner, ok = info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid {
		return nil, unavailable
	}
	derived := make([]string, 0, len(env)+2)
	for _, item := range env {
		name, _, _ := strings.Cut(item, "=")
		if name != "XDG_RUNTIME_DIR" && name != "DBUS_SESSION_BUS_ADDRESS" {
			derived = append(derived, item)
		}
	}
	return append(derived, "XDG_RUNTIME_DIR="+dir, "DBUS_SESSION_BUS_ADDRESS=unix:path="+bus), nil
}
