package mcp

import (
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestHandleGenKey_CreatesKeyAndUpdatesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthKey}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	keyPath := filepath.Join(dir, "id_test")
	out, err := handleGenKey(deps, map[string]any{
		"alias": "h", "path": keyPath, "reason": "rotate key",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "ssh-ed25519")

	cfg2, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, keyPath, cfg2.Servers["h"].KeyPath)
}

func TestHandleTailLogs_RequiresReason(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}
	out, err := handleTailLogs(deps, map[string]any{"alias": "h", "path": "/var/log/x"})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
}
