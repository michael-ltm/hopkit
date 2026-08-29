// Package config holds the persistent configuration model for sshm.
//
// The on-disk format is TOML at the path returned by ConfigPath(). Passwords
// are never stored in this file — auth=password servers read credentials
// from the OS keychain or prompt at connect time.
package config

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// CurrentVersion is the schema version this build understands.
const CurrentVersion = 5

// MaxDescriptionRunes keeps server descriptions useful in terminal menus and
// MCP results without allowing an accidental pasted document to bloat every
// inventory lookup.
const MaxDescriptionRunes = 500

const (
	MaxLabelRunes = 100
	MaxGroupRunes = 100
	MaxTags       = 32
	MaxTagRunes   = 64
	MaxNotesRunes = 4000
)

// Auth methods supported by Server.Auth.
const (
	AuthKey      = "key"
	AuthPassword = "password"
	AuthAgent    = "agent"
)

// Init states for Server.InitState.
const (
	InitRaw          = "raw"
	InitBootstrapped = "bootstrapped"
)

// Status values for Server.LastStatus.
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusUnknown = "unknown"
)

// Platform values describe the target operating system. They are routing
// metadata, not a substitute for live detection by the remote command.
const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
	PlatformMacOS   = "macos"
)

// Server is one managed remote host.
type Server struct {
	Label             string    `toml:"label,omitempty"`
	Description       string    `toml:"description,omitempty"`
	Platform          string    `toml:"platform,omitempty"`
	Host              string    `toml:"host"`
	Port              int       `toml:"port"`
	User              string    `toml:"user"`
	Auth              string    `toml:"auth"`
	KeyPath           string    `toml:"key_path,omitempty"`
	Tags              []string  `toml:"tags,omitempty"`
	Group             string    `toml:"group,omitempty"`
	Notes             string    `toml:"notes,omitempty"`
	InitState         string    `toml:"init_state,omitempty"`
	CreatedAt         time.Time `toml:"created_at,omitempty"`
	IdentityChangedAt time.Time `toml:"identity_changed_at,omitempty"`
	LastUsed          time.Time `toml:"last_used,omitempty"`
	LastChecked       time.Time `toml:"last_checked,omitempty"`
	LastSeen          time.Time `toml:"last_seen,omitempty"`
	LastStatus        string    `toml:"last_status,omitempty"`
	CleanupProtected  bool      `toml:"cleanup_protected,omitempty"`
	ProxyJump         string    `toml:"proxy_jump,omitempty"`
	ProxyCommand      string    `toml:"proxy_command,omitempty"`
	Proxy             string    `toml:"proxy,omitempty"` // e.g. "socks5://127.0.0.1:7890"
	Forwards          []string  `toml:"forwards,omitempty"`
}

// NormalizePlatform accepts CLI/UI spellings and returns the canonical value.
func NormalizePlatform(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown", "auto":
		return "", nil
	case "windows", "win":
		return PlatformWindows, nil
	case "linux":
		return PlatformLinux, nil
	case "macos", "darwin", "mac":
		return PlatformMacOS, nil
	default:
		return "", fmt.Errorf("platform must be windows, linux, macos, or unknown")
	}
}

// ProjectsUsingServer returns sorted project profiles that would become
// orphaned if alias were removed.
func ProjectsUsingServer(cfg *Config, alias string) []string {
	if cfg == nil {
		return nil
	}
	projects := make([]string, 0)
	for name, project := range cfg.Projects {
		if project != nil && project.Server == alias {
			projects = append(projects, name)
		}
	}
	sort.Strings(projects)
	return projects
}

// ServersUsingProxyJump returns aliases whose ProxyJump points at alias.
func ServersUsingProxyJump(cfg *Config, alias string) []string {
	if cfg == nil {
		return nil
	}
	var users []string
	for name, server := range cfg.Servers {
		if name != alias && server != nil && strings.TrimSpace(server.ProxyJump) == alias {
			users = append(users, name)
		}
	}
	sort.Strings(users)
	return users
}

// CleanupProtectionReasons explains why cleanup must not remove alias.
func CleanupProtectionReasons(cfg *Config, alias string) []string {
	if cfg == nil {
		return nil
	}
	server, ok := cfg.Servers[alias]
	if !ok || server == nil {
		return nil
	}
	var reasons []string
	if server.CleanupProtected {
		reasons = append(reasons, "manually protected")
	}
	if cfg.Default == alias {
		reasons = append(reasons, "default server")
	}
	if projects := ProjectsUsingServer(cfg, alias); len(projects) > 0 {
		reasons = append(reasons, "used by projects: "+strings.Join(projects, ", "))
	}
	if users := ServersUsingProxyJump(cfg, alias); len(users) > 0 {
		reasons = append(reasons, "proxy jump for: "+strings.Join(users, ", "))
	}
	return reasons
}

// EffectiveDescription preserves the value of older configs that used Notes
// as their only human-readable server description. New writes should use
// Description; Notes remains available for longer operational details.
func EffectiveDescription(server *Server) string {
	if server == nil {
		return ""
	}
	if description := strings.TrimSpace(server.Description); description != "" {
		return description
	}
	return strings.TrimSpace(server.Notes)
}

// ValidateDescription rejects terminal-control content and unreasonably long
// descriptions. Credential-like content is rejected at the CLI/MCP boundary,
// where the safety package is available and can return a masked error.
func ValidateDescription(description string) error {
	if strings.ContainsAny(description, "\x00\r\n") {
		return fmt.Errorf("description must be a single line")
	}
	if utf8.RuneCountInString(description) > MaxDescriptionRunes {
		return fmt.Errorf("description must be at most %d characters", MaxDescriptionRunes)
	}
	return nil
}

// ValidateServerMetadataBounds limits AI-visible metadata and local notes so
// accidental clipboard dumps cannot turn routine inventory reads into a data
// leak. This validates shape/size only; callers separately reject credentials.
func ValidateServerMetadataBounds(label, description string, tags []string, group, notes string) error {
	if err := ValidateDescription(description); err != nil {
		return err
	}
	for name, field := range map[string]struct {
		value string
		limit int
	}{
		"label": {label, MaxLabelRunes},
		"group": {group, MaxGroupRunes},
		"notes": {notes, MaxNotesRunes},
	} {
		if strings.ContainsRune(field.value, '\x00') {
			return fmt.Errorf("%s must not contain NUL", name)
		}
		if name != "notes" && strings.ContainsAny(field.value, "\r\n") {
			return fmt.Errorf("%s must be a single line", name)
		}
		if utf8.RuneCountInString(field.value) > field.limit {
			return fmt.Errorf("%s must be at most %d characters", name, field.limit)
		}
	}
	if len(tags) > MaxTags {
		return fmt.Errorf("tags must contain at most %d values", MaxTags)
	}
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "" || strings.ContainsAny(tag, "\x00\r\n") {
			return fmt.Errorf("tags must contain non-empty single-line values")
		}
		if utf8.RuneCountInString(tag) > MaxTagRunes {
			return fmt.Errorf("each tag must be at most %d characters", MaxTagRunes)
		}
	}
	return nil
}

// Project describes a local-to-remote build workspace and its artifact.
type Project struct {
	Server           string `toml:"server"`
	LocalRoot        string `toml:"local_root,omitempty"`
	RemoteWorkspace  string `toml:"remote_workspace"`
	RemoteRuns       string `toml:"remote_runs,omitempty"`
	ArtifactPath     string `toml:"artifact_path"`
	LocalArtifactDir string `toml:"local_artifact_dir,omitempty"`
	Shell            string `toml:"shell,omitempty"`
	BuildCommand     string `toml:"build_command,omitempty"`
	VerifyCommand    string `toml:"verify_command,omitempty"`
}

// UIConfig holds UI rendering preferences.
type UIConfig struct {
	Icons string `toml:"icons,omitempty"` // "unicode" | "ascii" | "" (auto)
	Color string `toml:"color,omitempty"` // "auto" | "always" | "never"
}

// Config is the top-level on-disk document.
type Config struct {
	Version  int                 `toml:"version"`
	Default  string              `toml:"default,omitempty"`
	UI       UIConfig            `toml:"ui,omitempty"`
	Servers  map[string]*Server  `toml:"servers"`
	Projects map[string]*Project `toml:"projects"`
}

// New returns an empty Config at the current schema version.
func New() *Config {
	return &Config{
		Version:  CurrentVersion,
		Servers:  map[string]*Server{},
		Projects: map[string]*Project{},
	}
}
