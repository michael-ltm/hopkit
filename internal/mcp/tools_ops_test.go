package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestHandleGenKey_CreatesKeyAndUpdatesConfig(t *testing.T) {
	// gen_key now always encrypts and persists to the real keystore (no
	// unencrypted escape hatch on the MCP path), so this exercises the real
	// keychain/ssh-agent. Opt-in only. See Task 7/8 notes.
	if os.Getenv("SSHM_KEYSTORE_E2E") == "" {
		t.Skip("set SSHM_KEYSTORE_E2E=1 to exercise the real keystore path")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	// Start with auth=password to verify gen_key flips it to key.
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthPassword}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	keyPath := filepath.Join(dir, "id_test")
	out, err := handleGenKey(context.Background(), deps, map[string]any{
		"alias": "h", "path": keyPath, "reason": "rotate key",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "ssh-ed25519")

	cfg2, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, keyPath, cfg2.Servers["h"].KeyPath)
	// Auth must now be key-based.
	require.Equal(t, config.AuthKey, cfg2.Servers["h"].Auth)
}

func TestHandleGenKey_PreservesAuthKeyIfAlreadyKey(t *testing.T) {
	// Same reason as above: gen_key now always hits the real keystore.
	if os.Getenv("SSHM_KEYSTORE_E2E") == "" {
		t.Skip("set SSHM_KEYSTORE_E2E=1 to exercise the real keystore path")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthKey}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	keyPath := filepath.Join(dir, "id_test2")
	out, err := handleGenKey(context.Background(), deps, map[string]any{
		"alias": "h", "path": keyPath, "reason": "rotate",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "ssh-ed25519")

	cfg2, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.AuthKey, cfg2.Servers["h"].Auth)
}

func TestHandleGenKey_EncryptsAndHidesPassphrase(t *testing.T) {
	// Opt-in only (real keystore side effects). See Task 7 note.
	if os.Getenv("SSHM_KEYSTORE_E2E") == "" {
		t.Skip("set SSHM_KEYSTORE_E2E=1 to exercise the real keystore path")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["srv"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthPassword}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	keyPath := filepath.Join(dir, "id_test3")
	res, err := handleGenKey(context.Background(), deps, map[string]any{
		"alias": "srv", "path": keyPath, "reason": "test",
	})
	require.NoError(t, err)
	m := res.(map[string]any)
	require.Equal(t, true, m["encrypted"])
	require.NotContains(t, m, "passphrase") // never returned
	require.Contains(t, m["recovery_file"].(string), ".passphrase")
}

func TestHandleTailLogs_RequiresReason(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}
	out, err := handleTailLogs(context.Background(), deps, map[string]any{"alias": "h", "path": "/var/log/x"})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
}

func TestClampLines(t *testing.T) {
	tests := []struct {
		in   int
		want int
	}{
		{0, defaultTailLines},  // zero → default
		{-5, defaultTailLines}, // negative → default
		{1, 1},                 // floor
		{100, 100},             // unchanged
		{5000, 5000},           // max
		{5001, maxTailLines},   // above max → clamped
		{99999, maxTailLines},  // way above max → clamped
	}
	for _, tt := range tests {
		got := clampLines(tt.in)
		require.Equal(t, tt.want, got, "clampLines(%d)", tt.in)
	}
}
