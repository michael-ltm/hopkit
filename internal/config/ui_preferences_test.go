package config

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestPreferencesSurviveLegacyServerWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := New()
	cfg.Servers["keep"] = &Server{Host: "example.invalid", User: "ops", Port: 22, Auth: "agent"}
	require.NoError(t, Save(path, cfg))
	prefs := UIConfig{Language: "zh-CN", Color: "never", Icons: "ascii"}
	require.NoError(t, SaveUIPreferences(path, prefs))
	// Model an old agent: it only knows TOML fields and rewrites the server file.
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	old, e := decodeConfig(raw)
	require.NoError(t, e)
	old.Servers["keep"].Description = "agent heartbeat"
	old.UI = UIConfig{}
	require.NoError(t, Save(path, old))
	loaded, e := Load(path)
	require.NoError(t, e)
	require.Equal(t, prefs, loaded.UI)
	require.Equal(t, "agent heartbeat", loaded.Servers["keep"].Description)
	require.NoError(t, os.WriteFile(path+".ui.json", []byte("broken preference file"), 0600))
	loaded, e = Load(path)
	require.NoError(t, e)
	require.Contains(t, loaded.Servers, "keep", "bad UI preferences must not block server access")
}

func TestCloudBindingsSurviveLegacyWritersButNotRouteChangesOrDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := New()
	cfg.Servers["cloud"] = &Server{Host: "example.invalid", User: "ops", Port: 22, Auth: AuthCloud, CloudEntry: "entry-id", CloudVault: "pinned-vault"}
	require.NoError(t, Save(path, cfg))
	require.NoError(t, SaveCloudBindings(path, cfg))
	cfg.Servers["cloud"].CloudEntry = ""
	cfg.Servers["cloud"].CloudVault = ""
	cfg.Servers["cloud"].Description = "old-agent-writer"
	require.NoError(t, Save(path, cfg))
	loaded, e := Load(path)
	require.NoError(t, e)
	require.Equal(t, "entry-id", loaded.Servers["cloud"].CloudEntry)
	require.NoError(t, Update(path, func(c *Config) error { c.Servers["cloud"].Label = "new-client-edit"; return nil }))
	loaded, e = Load(path)
	require.NoError(t, e)
	require.Equal(t, "pinned-vault", loaded.Servers["cloud"].CloudVault)
	cfg.Servers["cloud"].Host = "changed.invalid"
	require.NoError(t, Save(path, cfg))
	loaded, e = Load(path)
	require.NoError(t, e)
	require.Empty(t, loaded.Servers["cloud"].CloudEntry)
	delete(cfg.Servers, "cloud")
	require.NoError(t, Save(path, cfg))
	loaded, e = Load(path)
	require.NoError(t, e)
	require.Empty(t, loaded.Servers)
}
