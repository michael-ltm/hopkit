package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
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
	if !ok || s == nil {
		return nil, fmt.Errorf("unknown server %q (run `sshm ls` to see configured aliases)", alias)
	}
	return s, nil
}

// writeJSON emits v as indented JSON to w. If w is a bufio.Writer the
// caller is responsible for flushing after the call.
func writeJSON(w io.Writer, v any) error {
	if flagRedacted {
		var generic any
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(encoded, &generic); err != nil {
			return err
		}
		v = redactJSONValue("", generic)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func redactJSONValue(key string, value any) any {
	switch typed := value.(type) {
	case string:
		if isPrivateNotesKey(key) && typed != "" {
			return "<redacted private notes>"
		}
		if isSensitivePathKey(key) && typed != "" {
			return "<redacted path>"
		}
		return safety.MaskSecrets(typed)
	case []any:
		redacted := make([]any, len(typed))
		for index, item := range typed {
			redacted[index] = redactJSONValue(key, item)
		}
		return redacted
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for childKey, item := range typed {
			redacted[childKey] = redactJSONValue(childKey, item)
		}
		return redacted
	default:
		return value
	}
}

func isSensitivePathKey(key string) bool {
	key = strings.ToLower(key)
	compact := strings.ReplaceAll(key, "_", "")
	return compact == "key" || compact == "keypath" || compact == "recoveryfile" ||
		strings.HasSuffix(compact, "path") || strings.HasSuffix(compact, "root") ||
		strings.HasSuffix(compact, "workspace") || strings.HasSuffix(compact, "runs") ||
		strings.HasSuffix(compact, "dir")
}

func isPrivateNotesKey(key string) bool {
	return strings.EqualFold(strings.ReplaceAll(key, "_", ""), "notes")
}
