package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/michael-ltm/sshm/internal/safety"
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
	if cfg.Projects == nil {
		cfg.Projects = map[string]*Project{}
	}
	return cfg, nil
}

// Save atomically writes cfg to path with mode 0600. Creates parent dirs.
func Save(path string, cfg *Config) error {
	if err := validateProjectCredentials(cfg); err != nil {
		return err
	}
	if cfg.Version < CurrentVersion {
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
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("chmod config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}

func validateProjectCredentials(cfg *Config) error {
	projectNames := make([]string, 0, len(cfg.Projects))
	for name := range cfg.Projects {
		projectNames = append(projectNames, name)
	}
	sort.Strings(projectNames)

	for _, name := range projectNames {
		project := cfg.Projects[name]
		if project == nil {
			continue
		}
		fields := []struct {
			name  string
			value string
		}{
			{name: "local_root", value: project.LocalRoot},
			{name: "remote_workspace", value: project.RemoteWorkspace},
			{name: "remote_runs", value: project.RemoteRuns},
			{name: "artifact_path", value: project.ArtifactPath},
			{name: "local_artifact_dir", value: project.LocalArtifactDir},
			{name: "build_command", value: project.BuildCommand},
			{name: "verify_command", value: project.VerifyCommand},
		}
		for _, field := range fields {
			if safety.ContainsCredentialMaterial(field.value) {
				return fmt.Errorf("project %q field %q contains credential material", name, field.name)
			}
		}
	}
	return nil
}
