package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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
	return decodeConfig(data)
}

func decodeConfig(data []byte) (*Config, error) {
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
	// Before v5, LastSeen was the only persisted activity signal. Treat it as
	// conservative legacy usage evidence so an upgrade cannot suddenly classify
	// a previously active host as unknown and offer it for cleanup.
	if cfg.Version < 5 {
		for _, server := range cfg.Servers {
			if server != nil && server.LastUsed.IsZero() && !server.LastSeen.IsZero() {
				server.LastUsed = server.LastSeen
			}
		}
	}
	return cfg, nil
}

// Save atomically writes cfg to path with private file permissions. It creates
// parent directories and serializes with Update across sshm processes.
func Save(path string, cfg *Config) error {
	mu.Lock()
	defer mu.Unlock()

	unlock, err := lockConfigFile(path)
	if err != nil {
		return err
	}
	defer unlock()
	return saveUnlocked(path, cfg)
}

// saveUnlocked writes cfg while the caller holds both the in-process mutex
// and the per-config inter-process lock.
func saveUnlocked(path string, cfg *Config) error {
	return saveUnlockedIfUnchanged(path, cfg, nil)
}

type configSnapshot struct {
	data   []byte
	exists bool
}

func saveUnlockedIfUnchanged(path string, cfg *Config, expected *configSnapshot) error {
	if err := ValidateProjects(cfg); err != nil {
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
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("chmod config: %w", err)
	}
	if expected != nil {
		current, err := os.ReadFile(path)
		switch {
		case err == nil && !expected.exists:
			return fmt.Errorf("config changed outside sshm during update; retry")
		case err == nil && !bytes.Equal(current, expected.data):
			return fmt.Errorf("config changed outside sshm during update; retry")
		case errors.Is(err, os.ErrNotExist) && expected.exists:
			return fmt.Errorf("config changed outside sshm during update; retry")
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("re-read config before save: %w", err)
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}

var projectNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// ValidateProjects validates every reusable project profile before it is
// exposed by project MCP tools or persisted. Load intentionally does not call
// this function: a malformed optional profile must not prevent server-only
// reads, and callers such as Update need to be able to repair it.
func ValidateProjects(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	projectNames := make([]string, 0, len(cfg.Projects))
	for name := range cfg.Projects {
		projectNames = append(projectNames, name)
	}
	sort.Strings(projectNames)

	for _, name := range projectNames {
		if !projectNamePattern.MatchString(name) {
			return fmt.Errorf("project name is invalid")
		}
		if safety.ContainsCredentialMaterial(name) {
			return fmt.Errorf("project name contains credential material")
		}
		project := cfg.Projects[name]
		if project == nil {
			continue
		}
		if strings.ContainsAny(project.Server, "\x00\r\n") {
			return fmt.Errorf("project %q field %q contains invalid control characters", name, "server")
		}
		if !validProjectShell(project.Shell) {
			return fmt.Errorf("project %q field %q is invalid", name, "shell")
		}
		fields := []struct {
			name  string
			value string
		}{
			{name: "server", value: project.Server},
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

func validProjectShell(shell string) bool {
	switch shell {
	case "", "auto", "posix", "powershell", "cmd":
		return true
	default:
		return false
	}
}
