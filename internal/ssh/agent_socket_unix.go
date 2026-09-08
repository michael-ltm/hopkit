//go:build !windows

package ssh

import (
	"github.com/michael-ltm/sshm/internal/config"
	"os"
	"path/filepath"
	"syscall"
)

func ManagedAgentPath() string { return filepath.Join(config.ConfigDir(), "agent", "socket") }

func ownAgentSocket(path string) string {
	if path == "" {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) {
		return ""
	}
	return path
}
