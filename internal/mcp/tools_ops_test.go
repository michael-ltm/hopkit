package mcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
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

func TestTailCommandPOSIX(t *testing.T) {
	require.Equal(t, "tail -n 25 '/tmp/a b.log'", tailCommand("posix", "/tmp/a b.log", 25))
}

func TestTailCommandWindows(t *testing.T) {
	got := tailCommand("windows", `C:\Temp\a b.log`, 25)

	require.Contains(t, got, "powershell.exe -NoProfile -NonInteractive -EncodedCommand ")
	parts := strings.Fields(got)
	require.NotEmpty(t, parts)
	decoded, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	require.NoError(t, err)
	require.Zero(t, len(decoded)%2)
	words := make([]uint16, len(decoded)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(decoded[i*2:])
	}
	script := string(utf16.Decode(words))
	require.Contains(t, script, "Get-Content")
	require.Contains(t, script, "-LiteralPath 'C:\\Temp\\a b.log'")
	require.Contains(t, script, "-Tail 25")
}

func TestBuildTailLogsResultRejectsNonzeroExit(t *testing.T) {
	for _, platform := range []string{"posix", "windows"} {
		t.Run(platform, func(t *testing.T) {
			result := buildTailLogsResult("pc-e5", `C:\Temp\build.log`, platform, &sshpkg.ExecResult{
				ExitCode: 1,
				Stderr:   "log read denied TOKEN=topsecret",
			})

			errPayload, ok := result["error"].(map[string]string)
			require.True(t, ok)
			require.Equal(t, "exec", errPayload["kind"])
			require.Contains(t, errPayload["message"], "tail command exited 1")
			require.Contains(t, errPayload["message"], "log read denied TOKEN=***")
			require.NotContains(t, errPayload["message"], "topsecret")
		})
	}
}

func TestBuildTailLogsResultPreservesSuccessContract(t *testing.T) {
	result := buildTailLogsResult("prod", "/tmp/build.log", "posix", &sshpkg.ExecResult{
		ExitCode: 0,
		Stdout:   "last line\n",
	})

	require.Equal(t, map[string]any{
		"alias": "prod", "path": "/tmp/build.log", "platform": "posix", "lines": "last line\n",
	}, result)
}

func TestHandleTailLogsAuditsNonzeroExit(t *testing.T) {
	oldRunTailLogsRemote := runTailLogsRemote
	t.Cleanup(func() { runTailLogsRemote = oldRunTailLogsRemote })

	for _, platform := range []string{"posix", "windows"} {
		t.Run(platform, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			auditPath := filepath.Join(dir, "audit.jsonl")
			cfg := config.New()
			cfg.Servers["build"] = &config.Server{Host: "example.invalid", User: "builder", Auth: config.AuthAgent}
			require.NoError(t, config.Save(cfgPath, cfg))

			runTailLogsRemote = func(_ context.Context, _ Deps, _ *config.Server, gotPlatform, _ string, _ int) (string, *sshpkg.ExecResult, string, error) {
				return gotPlatform, &sshpkg.ExecResult{
					ExitCode: 7,
					Stderr:   "log read failed TOKEN=topsecret",
				}, "", nil
			}

			result, err := handleTailLogs(context.Background(), Deps{
				ConfigPath: cfgPath, AuditPath: auditPath,
			}, map[string]any{
				"alias": "build", "path": "/tmp/build.log", "platform": platform, "reason": "inspect failed build",
			})
			require.NoError(t, err)
			errPayload, ok := result.(map[string]any)["error"].(map[string]string)
			require.True(t, ok)
			require.Equal(t, "exec", errPayload["kind"])
			require.Contains(t, errPayload["message"], "tail command exited 7")
			require.Contains(t, errPayload["message"], "TOKEN=***")
			require.NotContains(t, errPayload["message"], "topsecret")

			auditData, err := os.ReadFile(auditPath)
			require.NoError(t, err)
			var entry struct {
				Tool   string `json:"tool"`
				Alias  string `json:"alias"`
				Reason string `json:"reason"`
				Result string `json:"result"`
			}
			require.NoError(t, json.Unmarshal(auditData, &entry))
			require.Equal(t, "tail_logs", entry.Tool)
			require.Equal(t, "build", entry.Alias)
			require.Equal(t, "inspect failed build", entry.Reason)
			require.Equal(t, "exit 7", entry.Result)
		})
	}
}

func TestHandleTailLogsAuditsRemoteErrors(t *testing.T) {
	oldRunTailLogsRemote := runTailLogsRemote
	t.Cleanup(func() { runTailLogsRemote = oldRunTailLogsRemote })

	for _, tt := range []struct {
		kind      string
		wantAudit string
		secret    string
	}{
		{kind: "ssh", wantAudit: "tail ssh failed", secret: "tail-ssh-secret"},
		{kind: "exec", wantAudit: "tail exec failed", secret: "tail-exec-secret"},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			auditPath := filepath.Join(dir, "audit.jsonl")
			cfg := config.New()
			cfg.Servers["build"] = &config.Server{Host: "example.invalid", User: "builder", Auth: config.AuthAgent}
			require.NoError(t, config.Save(cfgPath, cfg))

			runTailLogsRemote = func(_ context.Context, _ Deps, _ *config.Server, platform, _ string, _ int) (string, *sshpkg.ExecResult, string, error) {
				return platform, nil, tt.kind, errors.New("remote failure TOKEN=" + tt.secret)
			}
			out, err := handleTailLogs(context.Background(), Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
				"alias": "build", "path": "/tmp/build.log", "platform": "posix", "reason": "test tail failure",
			})
			require.NoError(t, err)
			errorPayload, ok := out.(map[string]any)["error"].(map[string]string)
			require.True(t, ok)
			require.Equal(t, tt.kind, errorPayload["kind"])

			entry := requireSingleAuditEntry(t, auditPath)
			require.Equal(t, "tail_logs", entry.Tool)
			require.Equal(t, "build", entry.Alias)
			require.Equal(t, "test tail failure", entry.Reason)
			require.Equal(t, tt.wantAudit, entry.Result)
			auditData, readErr := os.ReadFile(auditPath)
			require.NoError(t, readErr)
			require.NotContains(t, string(auditData), tt.secret)
		})
	}
}

func TestFinishDetachedLaunchAuditsAndPreservesMissingWindowsMetadata(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	launcher := buildDetachLauncher("windows", "npm run build", 123)
	stdout := "pid=4321\r\n"

	result := finishDetachedLaunch(Deps{AuditPath: auditPath}, "pc-e5", "build release", true, launcher, stdout)

	require.Equal(t, "pc-e5", result["alias"])
	require.Equal(t, true, result["detached"])
	require.Equal(t, "windows", result["platform"])
	require.Equal(t, stdout, result["stdout"])
	require.Equal(t, 4321, result["pid"])
	errPayload, ok := result["error"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, "exec", errPayload["kind"])

	auditData, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.Contains(t, string(auditData), `"tool":"exec"`)
	require.Contains(t, string(auditData), `"alias":"pc-e5"`)
	require.Contains(t, string(auditData), `"reason":"build release"`)
	require.Contains(t, string(auditData), "metadata")
	require.Contains(t, string(auditData), "unsafe=true")
}

func TestHandleTailLogsRejectsUnknownPlatformBeforeDial(t *testing.T) {
	result, err := handleTailLogs(context.Background(), Deps{
		ConfigPath: filepath.Join(t.TempDir(), "missing-config.toml"),
	}, map[string]any{
		"alias": "missing", "path": "/tmp/build.log", "platform": "plan9", "reason": "inspect build",
	})

	require.NoError(t, err)
	errPayload, ok := result.(map[string]any)["error"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, map[string]string{
		"kind": "bad_request", "message": "platform must be auto, posix, or windows",
	}, errPayload)
}

func TestTailLogsSchemaConstrainsPlatform(t *testing.T) {
	s, _ := NewServer(Deps{AllowWrite: true})
	tool := s.GetTool("tail_logs")
	require.NotNil(t, tool)
	property, ok := tool.Tool.InputSchema.Properties["platform"].(map[string]any)
	require.True(t, ok)
	values, ok := property["enum"].([]string)
	require.True(t, ok)
	require.ElementsMatch(t, []string{"auto", "posix", "windows"}, values)
	require.NotContains(t, tool.Tool.InputSchema.Required, "platform")
}
