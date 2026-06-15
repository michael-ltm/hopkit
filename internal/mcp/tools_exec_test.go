package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestExecTimeout(t *testing.T) {
	require.Equal(t, 60*time.Second, execTimeout(map[string]any{}), "absent -> 60s")
	require.Equal(t, time.Duration(0), execTimeout(map[string]any{"timeout_seconds": float64(0)}), "0 -> no timeout")
	require.Equal(t, 120*time.Second, execTimeout(map[string]any{"timeout_seconds": float64(120)}), "120 -> 120s")
	require.Equal(t, 60*time.Second, execTimeout(map[string]any{"timeout_seconds": float64(-5)}), "negative -> 60s")
}

func TestHandleExec_BlocksDangerousCommand(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthAgent}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleExec(context.Background(), deps, map[string]any{
		"alias": "h", "command": "rm -rf /", "reason": "cleanup",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
	require.Contains(t, js, "dangerous")
}

func TestHandleExec_UnsafeFlagBypassesFilter(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "203.0.113.1", User: "x", Auth: config.AuthAgent}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleExec(context.Background(), deps, map[string]any{
		"alias": "h", "command": "rm -rf /", "reason": "forced", "unsafe": true,
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.NotContains(t, js, "dangerous command blocked")
}

func TestHandleExec_RequiresReason(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}
	out, err := handleExec(context.Background(), deps, map[string]any{"alias": "h", "command": "ls"})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
}

func TestHandleExec_BlockedCommandIsAudited(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	auditPath := filepath.Join(dir, "audit.log")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthAgent}
	require.NoError(t, config.Save(cfgPath, cfg))
	deps := Deps{ConfigPath: cfgPath, AuditPath: auditPath, AllowWrite: true}

	_, err := handleExec(context.Background(), deps, map[string]any{
		"alias": "h", "command": "rm -rf /", "reason": "cleanup",
	})
	require.NoError(t, err)

	data, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "blocked")
	require.Contains(t, string(data), "exec")
}

func TestHandleExecMulti_RequiresReason(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleExecMulti(context.Background(), deps, map[string]any{
		"aliases": []any{"h"}, "command": "ls",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
}

func TestHandleExecMulti_RejectsEmptyAliases(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleExecMulti(context.Background(), deps, map[string]any{
		"aliases": []any{}, "command": "ls", "reason": "test",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
}

// TestHandleExecMulti_AggregatesUnknownAliases verifies the aggregation shape:
// unknown aliases short-circuit to not_found before any dial (no server
// needed), landing in failed; succeeded stays empty; results keeps one entry
// per dispatched alias for back-compat. Run with -race to exercise the
// concurrent map writes.
func TestHandleExecMulti_AggregatesUnknownAliases(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New())) // no servers
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleExecMulti(context.Background(), deps, map[string]any{
		"aliases": []any{"alpha", "beta"}, "command": "ls", "reason": "audit",
	})
	require.NoError(t, err)
	m := out.(map[string]any)

	results := m["results"].(map[string]any)
	require.Len(t, results, 2)
	require.Contains(t, results, "alpha")
	require.Contains(t, results, "beta")

	succeeded := m["succeeded"].([]string)
	require.Empty(t, succeeded)

	failed := m["failed"].(map[string]string)
	require.Contains(t, failed, "alpha")
	require.Contains(t, failed, "beta")
	require.Contains(t, failed["alpha"], "not_found")
}

// TestHandleExecMulti_InvalidEntriesReported verifies that non-string and empty
// alias entries are reported in failed without being dispatched, and that the
// back-compat results map is still present.
func TestHandleExecMulti_InvalidEntriesReported(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	deps := Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}

	out, err := handleExecMulti(context.Background(), deps, map[string]any{
		"aliases": []any{"", float64(42), "valid-but-unknown"}, "command": "ls", "reason": "audit",
	})
	require.NoError(t, err)
	m := out.(map[string]any)

	failed := m["failed"].(map[string]string)
	// empty string and the non-string entry are both invalid
	require.Contains(t, failed["<invalid #0>"], "invalid alias entry")
	require.Contains(t, failed["<invalid #1>"], "invalid alias entry")
	// the valid-looking alias was dispatched and failed as not_found
	require.Contains(t, failed["valid-but-unknown"], "not_found")

	require.Empty(t, m["succeeded"].([]string))
	require.Contains(t, m["results"].(map[string]any), "valid-but-unknown")
}
