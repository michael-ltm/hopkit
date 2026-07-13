package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
)

func requireSingleAuditEntry(t *testing.T, path string) safety.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1)
	var entry safety.Entry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
	return entry
}

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

func TestHandleExecAuditsRemoteFailures(t *testing.T) {
	oldDial := dialExecRemote
	oldRun := runExecRemoteCommand
	t.Cleanup(func() {
		dialExecRemote = oldDial
		runExecRemoteCommand = oldRun
	})

	tests := []struct {
		name      string
		kind      string
		wantAudit string
		secret    string
		configure func(*testing.T)
	}{
		{
			name: "SSH dial", kind: "ssh", wantAudit: "ssh failed", secret: "dial-secret",
			configure: func(t *testing.T) {
				dialExecRemote = func(_ *config.Server, _ sshpkg.BuildOpts) (*sshpkg.Client, error) {
					return nil, errors.New("dial failed TOKEN=dial-secret")
				}
				runExecRemoteCommand = func(_ context.Context, _ *sshpkg.Client, _ string) (*sshpkg.ExecResult, error) {
					t.Fatal("exec called after dial failure")
					return nil, nil
				}
			},
		},
		{
			name: "SSH exec", kind: "exec", wantAudit: "exec failed", secret: "exec-secret",
			configure: func(_ *testing.T) {
				dialExecRemote = func(_ *config.Server, _ sshpkg.BuildOpts) (*sshpkg.Client, error) {
					return &sshpkg.Client{}, nil
				}
				runExecRemoteCommand = func(_ context.Context, _ *sshpkg.Client, _ string) (*sshpkg.ExecResult, error) {
					return &sshpkg.ExecResult{}, errors.New("session failed TOKEN=exec-secret")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			auditPath := filepath.Join(dir, "audit.jsonl")
			cfg := config.New()
			cfg.Servers["build"] = &config.Server{Host: "example.invalid", User: "builder", Auth: config.AuthAgent}
			require.NoError(t, config.Save(cfgPath, cfg))
			tt.configure(t)

			out, err := handleExec(context.Background(), Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
				"alias": "build", "command": "echo ok", "reason": "test remote failure",
			})
			require.NoError(t, err)
			errorPayload, ok := out.(map[string]any)["error"].(map[string]string)
			require.True(t, ok)
			require.Equal(t, tt.kind, errorPayload["kind"])

			entry := requireSingleAuditEntry(t, auditPath)
			require.Equal(t, "exec", entry.Tool)
			require.Equal(t, "build", entry.Alias)
			require.Equal(t, "test remote failure", entry.Reason)
			require.Equal(t, tt.wantAudit, entry.Result)
			auditData, readErr := os.ReadFile(auditPath)
			require.NoError(t, readErr)
			require.NotContains(t, string(auditData), tt.secret)
		})
	}
}

func TestRunDetachedAuditsLauncherFailures(t *testing.T) {
	oldRun := runExecRemoteCommand
	t.Cleanup(func() { runExecRemoteCommand = oldRun })

	tests := []struct {
		name      string
		result    *sshpkg.ExecResult
		err       error
		wantAudit string
		secret    string
	}{
		{name: "timeout", err: context.DeadlineExceeded, wantAudit: "detach launcher timed out"},
		{name: "exec error", err: errors.New("launcher failed TOKEN=launcher-secret"), wantAudit: "detach launcher failed", secret: "launcher-secret"},
		{name: "nonzero exit", result: &sshpkg.ExecResult{ExitCode: 7, Stderr: "failed TOKEN=exit-secret"}, wantAudit: "detach launcher exit 7", secret: "exit-secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			runExecRemoteCommand = func(_ context.Context, _ *sshpkg.Client, _ string) (*sshpkg.ExecResult, error) {
				return tt.result, tt.err
			}

			out, err := runDetached(context.Background(), Deps{AuditPath: auditPath}, &sshpkg.Client{},
				"build", "echo ok", "test detach failure", false, "windows")
			require.NoError(t, err)
			_, ok := out.(map[string]any)["error"]
			require.True(t, ok)

			entry := requireSingleAuditEntry(t, auditPath)
			require.Equal(t, "exec", entry.Tool)
			require.Equal(t, "build", entry.Alias)
			require.Equal(t, "test detach failure", entry.Reason)
			require.Equal(t, tt.wantAudit, entry.Result)
			if tt.secret != "" {
				auditData, readErr := os.ReadFile(auditPath)
				require.NoError(t, readErr)
				require.NotContains(t, string(auditData), tt.secret)
			}
		})
	}
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
