package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func writeProjectTestConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath, auditPath := filepath.Join(dir, "config.toml"), filepath.Join(dir, "audit.log")
	cfg := config.New()
	cfg.Servers["pc-e5"] = &config.Server{Host: "10.0.0.5", User: "ming", Auth: config.AuthKey}
	cfg.Projects["b"] = &config.Project{Server: "pc-e5", RemoteWorkspace: `C:\b`, ArtifactPath: `C:\out\b.exe`, Shell: "powershell"}
	cfg.Projects["a"] = &config.Project{Server: "pc-e5", RemoteWorkspace: `C:\a`, ArtifactPath: `C:\out\a.exe`, Shell: "powershell"}
	require.NoError(t, config.Save(cfgPath, cfg))
	return cfgPath, auditPath
}

func TestListProjectsSortedAndCompact(t *testing.T) {
	cfgPath, auditPath := writeProjectTestConfig(t)
	out, err := handleListProjects(context.Background(), Deps{ConfigPath: cfgPath, AuditPath: auditPath}, nil)
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Less(t, strings.Index(js, `"a"`), strings.Index(js, `"b"`))
	require.NotContains(t, js, "build_command")
}

func TestGetProjectReturnsFullProfile(t *testing.T) {
	cfgPath, auditPath := writeProjectTestConfig(t)
	out, err := handleGetProject(context.Background(), Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{"project": "a"})
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Contains(t, js, `"remote_workspace": "C:\\a"`)
	require.Contains(t, js, `"artifact_path": "C:\\out\\a.exe"`)
}

func TestUpsertProjectRejectsUnknownServer(t *testing.T) {
	cfgPath, auditPath := writeProjectTestConfig(t)
	out, err := handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
		"project": "new", "server": "missing", "remote_workspace": "/opt/new",
		"artifact_path": "/opt/out/new", "reason": "add build profile",
	})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "unknown server")
}

func TestUpsertProjectCreatesAndAudits(t *testing.T) {
	cfgPath, auditPath := writeProjectTestConfig(t)
	_, err := handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
		"project": "new", "server": "pc-e5", "remote_workspace": `C:\new`,
		"artifact_path": `C:\out\new.exe`, "reason": "add build profile",
	})
	require.NoError(t, err)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, `C:\new`, cfg.Projects["new"].RemoteWorkspace)
	auditBytes, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.Contains(t, string(auditBytes), "upsert_project")
	require.Contains(t, string(auditBytes), "new")
}

func TestUpsertProjectPreservesAbsentAndClearsExplicitEmpty(t *testing.T) {
	cfgPath, auditPath := writeProjectTestConfig(t)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	cfg.Projects["a"].LocalRoot = "/local/a"
	cfg.Projects["a"].BuildCommand = "python build.py"
	require.NoError(t, config.Save(cfgPath, cfg))
	_, err = handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
		"project": "a", "local_root": "", "reason": "clear stale local mapping",
	})
	require.NoError(t, err)
	got, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Empty(t, got.Projects["a"].LocalRoot)
	require.Equal(t, "python build.py", got.Projects["a"].BuildCommand)
}
