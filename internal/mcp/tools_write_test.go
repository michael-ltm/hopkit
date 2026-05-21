package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestHandleAddServer_PersistsAndAudits(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	auditPath := filepath.Join(dir, "audit.log")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: auditPath, AllowWrite: true}

	out, err := handleAddServer(deps, map[string]any{
		"alias": "newbox", "host": "10.0.0.5", "user": "root",
		"auth": "agent", "reason": "spinning up CI runner",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "newbox")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Contains(t, cfg.Servers, "newbox")

	audit, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.Contains(t, string(audit), "add_server")
	require.Contains(t, string(audit), "newbox")
}

func TestHandleAddServer_RequiresReason(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleAddServer(deps, map[string]any{
		"alias": "x", "host": "1.2.3.4", "user": "root", "auth": "agent",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, strings.ToLower(js), "reason")
	require.Contains(t, js, "error")
}

func TestHandleRemoveServer_Deletes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	auditPath := filepath.Join(dir, "audit.log")
	cfg := config.New()
	cfg.Servers["gone"] = &config.Server{Host: "1.2.3.4"}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: auditPath, AllowWrite: true}

	_, err := handleRemoveServer(deps, map[string]any{"alias": "gone", "reason": "decommissioned"})
	require.NoError(t, err)
	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, reloaded.Servers, "gone")
}
