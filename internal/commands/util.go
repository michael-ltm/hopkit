package commands

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/michael-ltm/sshm/internal/config"
)

// configPath returns the active config path: --config override wins,
// otherwise the platform default.
func configPath() string {
	if flagConfigPath != "" {
		return flagConfigPath
	}
	return config.ConfigPath()
}

// loadConfig honors --config override, otherwise uses ConfigPath().
func loadConfig() (*config.Config, string, error) {
	path := configPath()
	cfg, err := config.Load(path)
	return cfg, path, err
}

// saveConfig writes to the same path used by loadConfig.
func saveConfig(cfg *config.Config) error {
	return config.Save(configPath(), cfg)
}

// resolveServer picks a server entry: explicit alias wins, otherwise the
// config-level default. Returns an error with the available alias list when
// resolution fails.
func resolveServer(cfg *config.Config, alias string) (*config.Server, error) {
	if alias == "" {
		alias = cfg.Default
	}
	if alias == "" {
		return nil, fmt.Errorf("no alias given and no default set — try `sshm ls` and pass an alias")
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return nil, fmt.Errorf("unknown server %q (run `sshm ls` to see configured aliases)", alias)
	}
	return s, nil
}

// writeJSON emits v as indented JSON to w. If w is a bufio.Writer the
// caller is responsible for flushing after the call.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
