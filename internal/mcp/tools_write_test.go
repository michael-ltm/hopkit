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

func TestHandleEditServer_AppliesAuthAndKeyPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "u", Auth: config.AuthAgent}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	_, err := handleEditServer(deps, map[string]any{
		"alias": "h", "reason": "switch to key auth",
		"auth": "key", "key_path": "/home/u/.ssh/id",
	})
	require.NoError(t, err)
	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.AuthKey, reloaded.Servers["h"].Auth)
	require.Equal(t, "/home/u/.ssh/id", reloaded.Servers["h"].KeyPath)
}

// Regression: when a caller supplies key_path but no auth, sshm used to default
// to agent and produce "no supported methods remain" failures because ssh-agent
// was empty. Now it infers key auth.
func TestHandleAddServer_InfersKeyAuthFromKeyPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	_, err := handleAddServer(deps, map[string]any{
		"alias": "kbox", "host": "1.2.3.4", "user": "root",
		"key_path": "/home/me/.ssh/id_ed25519",
		"reason":   "regression for key inference",
	})
	require.NoError(t, err)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.AuthKey, cfg.Servers["kbox"].Auth)
	require.Equal(t, "/home/me/.ssh/id_ed25519", cfg.Servers["kbox"].KeyPath)
}

// Without key_path or auth, it must still fall back to agent (existing behaviour).
func TestHandleAddServer_DefaultsToAgentWhenNothingProvided(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	_, err := handleAddServer(deps, map[string]any{
		"alias": "abox", "host": "1.2.3.4", "user": "root",
		"reason": "default agent fallback",
	})
	require.NoError(t, err)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.AuthAgent, cfg.Servers["abox"].Auth)
}

func TestHandleAddServer_RejectsMissingHost(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleAddServer(deps, map[string]any{
		"alias": "x", "user": "root", "auth": "agent", "reason": "test",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
	require.Contains(t, js, "host")
}

func TestHandleAddServer_RejectsBadAuth(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleAddServer(deps, map[string]any{
		"alias": "x", "host": "1.2.3.4", "user": "root",
		"auth": "pubkey", "reason": "test",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
}
