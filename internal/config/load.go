package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Load reads a Config from path. If the file does not exist, an empty
// Config at CurrentVersion is returned with nil error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return New(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := New()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Version > CurrentVersion {
		return nil, fmt.Errorf("unsupported config version %d (this build supports up to %d)", cfg.Version, CurrentVersion)
	}
	if cfg.Servers == nil {
		cfg.Servers = map[string]*Server{}
	}
	return cfg, nil
}

// Save atomically writes cfg to path with mode 0600. Creates parent dirs.
func Save(path string, cfg *Config) error {
	if cfg.Version == 0 {
		cfg.Version = CurrentVersion
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := toml.NewEncoder(tmp).Encode(cfg); err != nil {
		tmp.Close()
		return fmt.Errorf("encode toml: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
