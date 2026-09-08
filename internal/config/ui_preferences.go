package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// UI preferences live outside the server document. Older agents rewrite TOML
// without preserving unknown fields; a sync must never reset language settings.
func applyUIPreferences(path string, cfg *Config) *Config {
	var prefs UIConfig
	if data, e := os.ReadFile(path + ".ui.json"); e == nil && len(data) < 8192 && json.Unmarshal(data, &prefs) == nil {
		cfg.UI = prefs
	}
	// A damaged optional UI file must not prevent SSH or MCP access.
	return cfg
}
func SaveUIPreferences(path string, prefs UIConfig) error {
	return saveLocalJSON(path+".ui.json", prefs)
}

func saveLocalJSON(target string, value any) error {
	mu.Lock()
	defer mu.Unlock()
	unlock, e := lockConfigFile(target)
	if e != nil {
		return e
	}
	defer unlock()
	data, e := json.Marshal(value)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(target), ".ui-*")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if _, e = tmp.Write(data); e == nil {
		e = tmp.Sync()
	}
	closeErr := tmp.Close()
	if e != nil {
		return fmt.Errorf("save UI preferences: %w", e)
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), target)
}
