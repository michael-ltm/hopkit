package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir returns the directory that holds sshm configuration.
//
// Resolution order:
//   - Windows: %APPDATA%/sshm
//   - Unix:    $XDG_CONFIG_HOME/sshm (if set) else ~/.config/sshm
func ConfigDir() string {
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, "sshm")
		}
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "sshm")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Last-ditch: cwd. We never want to crash on missing home.
		return filepath.Join(".", ".sshm")
	}
	return filepath.Join(home, ".config", "sshm")
}

// ConfigPath returns the full path to config.toml.
func ConfigPath() string { return filepath.Join(ConfigDir(), "config.toml") }

// AuditPath returns the full path to audit.log.
func AuditPath() string { return filepath.Join(ConfigDir(), "audit.log") }
