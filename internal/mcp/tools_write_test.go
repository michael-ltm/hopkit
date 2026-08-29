package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	_, err := handleRemoveServer(deps, map[string]any{"alias": "gone", "confirm_alias": "gone", "reason": "decommissioned"})
	require.NoError(t, err)
	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, reloaded.Servers, "gone")
}

func TestHandleRemoveServerRequiresExactAliasConfirmation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["keep"] = &config.Server{Host: "1.2.3.4"}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true}

	out, err := handleRemoveServer(deps, map[string]any{
		"alias": "keep", "confirm_alias": "wrong", "reason": "test confirmation",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "confirmation_required")
	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Contains(t, reloaded.Servers, "keep")
}

func TestHandleRemoveServerRefusesReferencedAlias(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["builder"] = &config.Server{Host: "1.2.3.4"}
	cfg.Projects["app"] = &config.Project{Server: "builder", RemoteWorkspace: "/srv/app", ArtifactPath: "/srv/app.tgz"}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true}

	out, err := handleRemoveServer(deps, map[string]any{
		"alias": "builder", "confirm_alias": "builder", "reason": "decommission",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "conflict")
	require.Contains(t, js, "app")
}

func TestHandleRemoveServerRefusesProxyJumpAliasWithDependentAliases(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["gateway"] = &config.Server{Host: "10.0.0.1"}
	cfg.Servers["zeta"] = &config.Server{Host: "10.0.0.2", ProxyJump: "gateway"}
	cfg.Servers["alpha"] = &config.Server{Host: "10.0.0.3", ProxyJump: "gateway"}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true}

	out, err := handleRemoveServer(deps, map[string]any{
		"alias": "gateway", "confirm_alias": "gateway", "reason": "decommission",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "conflict")
	require.Contains(t, js, "servers using it as ProxyJump: alpha, zeta")

	reloaded, loadErr := config.Load(cfgPath)
	require.NoError(t, loadErr)
	require.Contains(t, reloaded.Servers, "gateway")
}

func TestHandleEditServerRequiresConfirmationForConnectionChanges(t *testing.T) {
	deps := Deps{ConfigPath: writeTestConfig(t), AuditPath: filepath.Join(t.TempDir(), "audit.log"), AllowWrite: true}
	out, err := handleEditServer(deps, map[string]any{
		"alias": "prod", "host": "198.51.100.10", "reason": "move host",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "confirmation_required")
}

func TestHandleEditServerConnectionIdentityChangeClearsActivityButKeepsCreatedAt(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		value any
	}{
		{name: "host", field: "host", value: "5.6.7.8"},
		{name: "port", field: "port", value: float64(2222)},
		{name: "user", field: "user", value: "new"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			active := created.Add(time.Hour)
			cfg := config.New()
			cfg.Servers["h"] = &config.Server{
				Host: "1.2.3.4", Port: 22, User: "old", Auth: config.AuthAgent,
				CreatedAt: created, LastUsed: active, LastSeen: active,
				LastChecked: active, LastStatus: config.StatusOnline,
			}
			require.NoError(t, config.Save(cfgPath, cfg))
			deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true}

			args := map[string]any{
				"alias": "h", "reason": "change connection identity", "confirm_alias": "h",
				test.field: test.value,
			}
			beforeEdit := time.Now().UTC()
			_, err := handleEditServer(deps, args)
			require.NoError(t, err)
			afterEdit := time.Now().UTC()

			loaded, err := config.Load(cfgPath)
			require.NoError(t, err)
			server := loaded.Servers["h"]
			require.Equal(t, created, server.CreatedAt)
			require.False(t, server.IdentityChangedAt.Before(beforeEdit))
			require.False(t, server.IdentityChangedAt.After(afterEdit))
			require.True(t, server.LastUsed.IsZero())
			require.True(t, server.LastSeen.IsZero())
			require.True(t, server.LastChecked.IsZero())
			require.Empty(t, server.LastStatus)
		})
	}
}

func TestHandleEditServerMetadataAndSameIdentityPreserveActivity(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	active := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{
		Host: "1.2.3.4", Port: 22, User: "old", Auth: config.AuthAgent,
		LastUsed: active, LastSeen: active, LastChecked: active, LastStatus: config.StatusOnline,
	}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true}

	_, err := handleEditServer(deps, map[string]any{
		"alias": "h", "reason": "refresh description", "confirm_alias": "h",
		"host": "1.2.3.4", "description": "updated",
	})
	require.NoError(t, err)

	loaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	server := loaded.Servers["h"]
	require.Equal(t, active, server.LastUsed)
	require.Equal(t, active, server.LastSeen)
	require.Equal(t, active, server.LastChecked)
	require.Equal(t, config.StatusOnline, server.LastStatus)
	require.True(t, server.IdentityChangedAt.IsZero())
}

func TestHandleAddServerRejectsCredentialInProxy(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true}
	out, err := handleAddServer(deps, map[string]any{
		"alias": "proxybox", "host": "example.com", "reason": "test",
		"proxy": "socks5://alice:plaintext@example.net:1080",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "bad_request")
	require.NotContains(t, js, "plaintext")
}

func TestHandleEditServerUpdatesAndClearsDiscoveryMetadata(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["lab"] = &config.Server{Host: "1.2.3.4", Description: "old", Tags: []string{"old"}}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true}

	_, err := handleEditServer(deps, map[string]any{
		"alias": "lab", "reason": "document reverse lab",
		"description": "Windows x64 dynamic debugging lab", "tags": []any{"windows", "dynamic-debug"},
		"group": "reverse",
	})
	require.NoError(t, err)
	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "Windows x64 dynamic debugging lab", reloaded.Servers["lab"].Description)
	require.Equal(t, []string{"windows", "dynamic-debug"}, reloaded.Servers["lab"].Tags)
	require.Equal(t, "reverse", reloaded.Servers["lab"].Group)

	_, err = handleEditServer(deps, map[string]any{
		"alias": "lab", "reason": "clear stale discovery metadata",
		"description": "", "tags": []any{}, "group": "",
	})
	require.NoError(t, err)
	reloaded, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.Empty(t, reloaded.Servers["lab"].Description)
	require.Empty(t, reloaded.Servers["lab"].Tags)
	require.Empty(t, reloaded.Servers["lab"].Group)
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
		"auth": "key", "key_path": "/home/u/.ssh/id", "confirm_alias": "h",
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

func TestHandleAddServer_PersistsProxyFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	_, err := handleAddServer(deps, map[string]any{
		"alias": "pbox", "host": "10.0.0.9", "user": "root", "auth": "agent",
		"proxy": "socks5://127.0.0.1:7890", "proxy_jump": "bastion",
		"proxy_command": "nc -X 5 -x 127.0.0.1:7890 %h %p",
		"reason":        "behind a SOCKS proxy",
	})
	require.NoError(t, err)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	s := cfg.Servers["pbox"]
	require.NotNil(t, s)
	require.Equal(t, "socks5://127.0.0.1:7890", s.Proxy)
	require.Equal(t, "bastion", s.ProxyJump)
	require.Equal(t, "nc -X 5 -x 127.0.0.1:7890 %h %p", s.ProxyCommand)
}

func TestHandleEditServer_UpdatesProxyFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "u", Auth: config.AuthAgent, Proxy: "old:1"}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	// Only proxy_jump is provided; proxy must be left untouched (matches the
	// overwrite-only-when-non-empty convention used by other optional fields).
	_, err := handleEditServer(deps, map[string]any{
		"alias": "h", "reason": "add bastion", "proxy_jump": "jump.example", "confirm_alias": "h",
	})
	require.NoError(t, err)
	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "jump.example", reloaded.Servers["h"].ProxyJump)
	require.Equal(t, "old:1", reloaded.Servers["h"].Proxy, "unspecified proxy must be preserved")

	// Now set proxy and proxy_command.
	_, err = handleEditServer(deps, map[string]any{
		"alias": "h", "reason": "set socks", "proxy": "socks5://127.0.0.1:1080",
		"proxy_command": "nc %h %p", "confirm_alias": "h",
	})
	require.NoError(t, err)
	reloaded, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "socks5://127.0.0.1:1080", reloaded.Servers["h"].Proxy)
	require.Equal(t, "nc %h %p", reloaded.Servers["h"].ProxyCommand)
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
