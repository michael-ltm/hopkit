package commands

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_UsesOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.toml")
	flagConfigPath = path
	t.Cleanup(func() { flagConfigPath = "" })

	cfg, p, err := loadConfig()
	require.NoError(t, err)
	require.Equal(t, path, p)
	require.Equal(t, config.CurrentVersion, cfg.Version)
}

func TestWriteJSONRedactedMasksSecretsAndPaths(t *testing.T) {
	flagRedacted = true
	t.Cleanup(func() { flagRedacted = false })
	var out bytes.Buffer
	require.NoError(t, writeJSON(&out, map[string]any{
		"host":    "203.0.113.9",
		"KeyPath": "/Users/alice/.ssh/id_ed25519",
		"Notes":   "customer identity and private topology",
		"command": "curl --password hunter2 https://example.com",
	}))
	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, "203.0.*.*", got["host"])
	require.Equal(t, "<redacted path>", got["KeyPath"])
	require.Equal(t, "<redacted private notes>", got["Notes"])
	require.NotContains(t, got["command"], "hunter2")
}

func TestResolveServer_ErrorsOnUnknownAlias(t *testing.T) {
	cfg := config.New()
	_, err := resolveServer(cfg, "nope")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown server")
}

func TestResolveServer_UsesDefaultWhenAliasEmpty(t *testing.T) {
	cfg := config.New()
	cfg.Default = "prod"
	cfg.Servers["prod"] = &config.Server{Host: "1.1.1.1"}
	srv, err := resolveServer(cfg, "")
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1", srv.Host)
}

func TestResolveServer_ErrorsWhenAliasEmptyAndNoDefault(t *testing.T) {
	cfg := config.New() // cfg.Default == ""
	_, err := resolveServer(cfg, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no alias given")
}
