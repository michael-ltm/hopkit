// Package config holds the persistent configuration model for sshm.
//
// The on-disk format is TOML at the path returned by ConfigPath(). Passwords
// are never stored in this file — auth=password servers read credentials
// from the OS keychain or prompt at connect time.
package config

import "time"

// CurrentVersion is the schema version this build understands.
const CurrentVersion = 2

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

// Server is one managed remote host.
type Server struct {
	Label        string    `toml:"label,omitempty"`
	Host         string    `toml:"host"`
	Port         int       `toml:"port"`
	User         string    `toml:"user"`
	Auth         string    `toml:"auth"`
	KeyPath      string    `toml:"key_path,omitempty"`
	Tags         []string  `toml:"tags,omitempty"`
	Group        string    `toml:"group,omitempty"`
	Notes        string    `toml:"notes,omitempty"`
	InitState    string    `toml:"init_state,omitempty"`
	LastSeen     time.Time `toml:"last_seen,omitempty"`
	LastStatus   string    `toml:"last_status,omitempty"`
	ProxyJump    string    `toml:"proxy_jump,omitempty"`
	ProxyCommand string    `toml:"proxy_command,omitempty"`
	Proxy        string    `toml:"proxy,omitempty"` // e.g. "socks5://127.0.0.1:7890"
	Forwards     []string  `toml:"forwards,omitempty"`
}

// UIConfig holds UI rendering preferences.
type UIConfig struct {
	Icons string `toml:"icons,omitempty"` // "unicode" | "ascii" | "" (auto)
	Color string `toml:"color,omitempty"` // "auto" | "always" | "never"
}

// Config is the top-level on-disk document.
type Config struct {
	Version int                `toml:"version"`
	Default string             `toml:"default,omitempty"`
	UI      UIConfig           `toml:"ui,omitempty"`
	Servers map[string]*Server `toml:"servers"`
}

// New returns an empty Config at the current schema version.
func New() *Config {
	return &Config{Version: CurrentVersion, Servers: map[string]*Server{}}
}
