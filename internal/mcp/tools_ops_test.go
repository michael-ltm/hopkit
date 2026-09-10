package mcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestHandleGenKeyRequiresProtectedPassphraseFile(t *testing.T) {
	for _, kind := range []string{"missing", "insecure", "symlink", "inline"} {
		t.Run(kind, func(t *testing.T) {
			if runtime.GOOS == "windows" && (kind == "insecure" || kind == "symlink") {
				t.Skip("Unix file protections")
			}
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			keyPath := filepath.Join(dir, "key")
			cfg := config.New()
			cfg.Servers["srv"] = &config.Server{Host: "example.invalid", Auth: config.AuthPassword}
			require.NoError(t, config.Save(cfgPath, cfg))
			args := map[string]any{"alias": "srv", "path": keyPath, "reason": "generate key"}
			phrasePath := filepath.Join(dir, "secret")
			switch kind {
			case "insecure":
				require.NoError(t, os.WriteFile(phrasePath, []byte("unique-secret-marker"), 0644))
				require.NoError(t, os.Chmod(phrasePath, 0644))
				args["passphrase_file"] = phrasePath
			case "symlink":
				require.NoError(t, os.WriteFile(phrasePath, []byte("unique-secret-marker"), 0600))
				link := filepath.Join(dir, "link")
				require.NoError(t, os.Symlink(phrasePath, link))
				args["passphrase_file"] = link
			case "inline":
				args["passphrase"] = "unique-secret-marker"
			}
			out, err := handleGenKey(context.Background(), Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "audit")}, args)
			require.NoError(t, err)
			js, err := jsonResult(out)
			require.NoError(t, err)
			require.Contains(t, js, "error")
			require.NotContains(t, js, "unique-secret-marker")
			for _, path := range []string{keyPath, keyPath + ".pub", keyPath + ".passphrase"} {
				require.NoFileExists(t, path)
			}
		})
	}
}

func TestHandleGenKeyUsesSuppliedPassphraseWithoutSidecar(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("isolated Linux agent; other OS keystores need opt-in integration")
	}
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "absent-agent"))
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	keyPath := filepath.Join(dir, "key")
	phrasePath := filepath.Join(dir, "secret")
	auditPath := filepath.Join(dir, "audit")
	const phrase = "unique-secret-marker"
	require.NoError(t, os.WriteFile(phrasePath, []byte(phrase+"\n"), 0600))
	cfg := config.New()
	cfg.Servers["srv"] = &config.Server{Host: "example.invalid", Auth: config.AuthPassword}
	require.NoError(t, config.Save(cfgPath, cfg))
	out, err := handleGenKey(context.Background(), Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{"alias": "srv", "path": keyPath, "passphrase_file": phrasePath, "reason": "generate key"})
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.NotContains(t, js, "error")
	require.NotContains(t, js, phrase)
	require.NotContains(t, js, "recovery_file")
	data, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	_, err = gssh.ParsePrivateKey(data)
	require.Error(t, err)
	_, err = gssh.ParsePrivateKeyWithPassphrase(data, []byte(phrase))
	require.NoError(t, err)
	require.NoFileExists(t, keyPath+".passphrase")
	auditData, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.NotContains(t, string(auditData), phrase)
	inputAfter, err := os.ReadFile(phrasePath)
	require.NoError(t, err)
	require.Equal(t, phrase+"\n", string(inputAfter))
	updated, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, keyPath, updated.Servers["srv"].KeyPath)
	require.Equal(t, config.AuthKey, updated.Servers["srv"].Auth)
}

func TestGenKeySchemaRequiresFileAndRejectsSecretInputs(t *testing.T) {
	s, _ := NewServer(Deps{AllowWrite: true})
	tool := s.GetTool("gen_key")
	require.NotNil(t, tool)
	require.Contains(t, tool.Tool.InputSchema.Required, "passphrase_file")
	require.NotContains(t, tool.Tool.InputSchema.Properties, "passphrase")
	require.Equal(t, false, tool.Tool.InputSchema.AdditionalProperties)
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

			runTailLogsRemote = func(_ context.Context, _ Deps, _ string, _ *config.Server, gotPlatform, _ string, _ int) (string, *sshpkg.ExecResult, string, error) {
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

			runTailLogsRemote = func(_ context.Context, _ Deps, _ string, _ *config.Server, platform, _ string, _ int) (string, *sshpkg.ExecResult, string, error) {
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
