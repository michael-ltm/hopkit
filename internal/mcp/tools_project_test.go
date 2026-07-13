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

func TestGetProjectUnknownListsAvailableProjectsSorted(t *testing.T) {
	cfgPath, auditPath := writeProjectTestConfig(t)
	out, err := handleGetProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{"project": "missing"})
	require.NoError(t, err)

	result, ok := out.(map[string]any)
	require.True(t, ok)
	errorPayload, ok := result["error"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, "not_found", errorPayload["kind"])
	require.Equal(t, `unknown project "missing"; available projects: a, b`, errorPayload["message"])
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

func TestUpsertProjectRejectsCredentialFieldsWithoutModifyingDisk(t *testing.T) {
	fields := []struct {
		name         string
		value        string
		secretNeedle string
	}{
		{name: "local_root", value: "/src/TOKEN=local-root-secret", secretNeedle: "local-root-secret"},
		{name: "remote_workspace", value: "https://user:workspace-secret@example.com/repo", secretNeedle: "workspace-secret"},
		{name: "remote_runs", value: "Authorization: Bearer runs-secret", secretNeedle: "runs-secret"},
		{name: "artifact_path", value: "/tmp/ghp_abcdefghijklmnopqrstuvwxyz0123456789", secretNeedle: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{name: "local_artifact_dir", value: "TOKEN=artifact-dir-secret", secretNeedle: "artifact-dir-secret"},
		{name: "build_command", value: "builder --password build-secret", secretNeedle: "build-secret"},
		{name: "verify_command", value: "TOKEN=verify-secret go test ./...", secretNeedle: "verify-secret"},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			cfgPath, auditPath := writeProjectTestConfig(t)
			before, err := os.ReadFile(cfgPath)
			require.NoError(t, err)

			out, err := handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
				"project": "a", "reason": "test credential rejection", field.name: field.value,
			})
			require.NoError(t, err)
			result, ok := out.(map[string]any)
			require.True(t, ok)
			errorPayload, ok := result["error"].(map[string]string)
			require.True(t, ok)
			require.Equal(t, "bad_request", errorPayload["kind"])
			require.Contains(t, errorPayload["message"], field.name)
			require.NotContains(t, errorPayload["message"], field.secretNeedle)

			after, readErr := os.ReadFile(cfgPath)
			require.NoError(t, readErr)
			require.Equal(t, before, after)
		})
	}
}

func TestWrapProjectCommandPOSIX(t *testing.T) {
	got, err := wrapProjectCommand("posix", "/opt/my app", "npm test")
	require.NoError(t, err)
	require.Equal(t, "cd '/opt/my app' && npm test", got)
}

func TestWrapProjectCommandPowerShellUsesEncodedCommand(t *testing.T) {
	got, err := wrapProjectCommand("powershell", `C:\code\my app`, "python build.py")
	require.NoError(t, err)
	require.Contains(t, got, "powershell.exe -NoProfile -NonInteractive -EncodedCommand ")
}

func TestWrapProjectCommandCmd(t *testing.T) {
	got, err := wrapProjectCommand("cmd", `C:\code\app`, "build.cmd")
	require.NoError(t, err)
	require.Equal(t, `cmd.exe /d /s /c "cd /d ""C:\code\app"" && build.cmd"`, got)
}

func TestWrapProjectCommandRejectsInvalidWorkdir(t *testing.T) {
	for name, workdir := range map[string]string{
		"nul":              "/opt/app\x00next",
		"line feed":        "/opt/app\nnext",
		"carriage return":  "/opt/app\rnext",
		"cmd double quote": `C:\code\"app`,
	} {
		t.Run(name, func(t *testing.T) {
			shell := "posix"
			if name == "cmd double quote" {
				shell = "cmd"
			}
			_, err := wrapProjectCommand(shell, workdir, "echo ok")
			require.Error(t, err)
		})
	}
}

func TestProjectWorkdirSelectsPOSIXPaths(t *testing.T) {
	project := &config.Project{
		RemoteWorkspace: "/srv/app",
		RemoteRuns:      "/srv/runs/app",
		ArtifactPath:    "/srv/artifacts/app/latest.tar.gz",
	}

	for selector, want := range map[string]string{
		"":                "/srv/app",
		"workspace":       "/srv/app",
		"runs":            "/srv/runs/app",
		"artifact_parent": "/srv/artifacts/app",
	} {
		t.Run(selector, func(t *testing.T) {
			got, err := projectWorkdir(project, selector)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestProjectWorkdirSelectsWindowsPaths(t *testing.T) {
	project := &config.Project{
		RemoteWorkspace: `C:\code\app`,
		RemoteRuns:      `C:\runs\app`,
		ArtifactPath:    `C:\artifacts\app\latest.exe`,
	}

	for selector, want := range map[string]string{
		"":                `C:\code\app`,
		"workspace":       `C:\code\app`,
		"runs":            `C:\runs\app`,
		"artifact_parent": `C:\artifacts\app`,
	} {
		t.Run(selector, func(t *testing.T) {
			got, err := projectWorkdir(project, selector)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestResolveProjectShell(t *testing.T) {
	for name, tc := range map[string]struct {
		configured string
		workdir    string
		want       string
	}{
		"empty POSIX":         {workdir: "/srv/app", want: "posix"},
		"auto POSIX":          {configured: "auto", workdir: "/srv/app", want: "posix"},
		"auto drive path":     {configured: "auto", workdir: `C:\code\app`, want: "powershell"},
		"auto UNC path":       {configured: "auto", workdir: `\\server\share\app`, want: "powershell"},
		"explicit POSIX":      {configured: "posix", workdir: `C:\code\app`, want: "posix"},
		"explicit PowerShell": {configured: "powershell", workdir: "/srv/app", want: "powershell"},
		"explicit cmd":        {configured: "cmd", workdir: "/srv/app", want: "cmd"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resolveProjectShell(tc.configured, tc.workdir)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func writeExecProjectTestConfig(t *testing.T) (string, string) {
	t.Helper()
	cfgPath, auditPath := writeProjectTestConfig(t)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	cfg.Projects["project_ajie"] = &config.Project{
		Server:          "pc-e5",
		RemoteWorkspace: `C:\sshm\workspaces\project_ajie`,
		RemoteRuns:      `C:\sshm\runs\project_ajie`,
		ArtifactPath:    `C:\sshm\artifacts\project_ajie\latest\ajie_publish_tool.exe`,
		Shell:           "powershell",
	}
	require.NoError(t, config.Save(cfgPath, cfg))
	return cfgPath, auditPath
}

func TestHandleExecProjectForwardsWrappedCommandAndAddsMetadata(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })

	var forwarded map[string]any
	runProjectExec = func(_ context.Context, _ Deps, args map[string]any) (any, error) {
		forwarded = args
		return map[string]any{
			"exit": 0, "stdout": "built", "stderr": "", "truncated": true,
		}, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{
		"project": "project_ajie", "command": "python build.py", "reason": "build release",
		"unsafe": true, "timeout_seconds": float64(900), "detach": true, "platform": "windows",
	})
	require.NoError(t, err)
	require.Equal(t, "pc-e5", forwarded["alias"])
	require.Equal(t, "[project:project_ajie] build release", forwarded["reason"])
	require.Equal(t, true, forwarded["unsafe"])
	require.Equal(t, float64(900), forwarded["timeout_seconds"])
	require.Equal(t, true, forwarded["detach"])
	require.Equal(t, "windows", forwarded["platform"])
	wantCommand, err := wrapProjectCommand("powershell", `C:\sshm\workspaces\project_ajie`, "python build.py")
	require.NoError(t, err)
	require.Equal(t, wantCommand, forwarded["command"])

	result, ok := out.(map[string]any)
	require.True(t, ok)
	require.Equal(t, "project_ajie", result["project"])
	require.Equal(t, "pc-e5", result["alias"])
	require.Equal(t, `C:\sshm\workspaces\project_ajie`, result["workdir"])
	require.Equal(t, "powershell", result["shell"])
	require.Equal(t, 0, result["exit"])
	require.Equal(t, "built", result["stdout"])
	require.Equal(t, "", result["stderr"])
	require.Equal(t, true, result["truncated"])
}

func TestHandleExecProjectDerivesWindowsDetachPlatformFromPowerShell(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform any
		present  bool
	}{
		{name: "platform omitted"},
		{name: "platform auto", platform: "auto", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath, auditPath := writeExecProjectTestConfig(t)
			oldRunProjectExec := runProjectExec
			t.Cleanup(func() { runProjectExec = oldRunProjectExec })

			var forwarded map[string]any
			runProjectExec = func(_ context.Context, _ Deps, args map[string]any) (any, error) {
				forwarded = args
				return map[string]any{"detached": true}, nil
			}
			args := map[string]any{
				"project": "project_ajie", "command": "python build.py",
				"reason": "build release", "detach": true,
			}
			if tc.present {
				args["platform"] = tc.platform
			}

			_, err := handleExecProject(context.Background(), Deps{
				ConfigPath: cfgPath, AuditPath: auditPath,
			}, args)
			require.NoError(t, err)
			require.Equal(t, "windows", forwarded["platform"])
		})
	}
}

func TestHandleExecProjectPreservesExplicitDetachPlatform(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })

	var forwarded map[string]any
	runProjectExec = func(_ context.Context, _ Deps, args map[string]any) (any, error) {
		forwarded = args
		return map[string]any{"detached": true}, nil
	}

	_, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{
		"project": "project_ajie", "command": "python build.py", "reason": "build release",
		"detach": true, "platform": "posix",
	})
	require.NoError(t, err)
	require.Equal(t, "posix", forwarded["platform"])
}

func TestHandleExecProjectRejectsInvalidPlatformBeforeExec(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		t.Fatal("exec called with an invalid platform")
		return nil, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{
		"project": "project_ajie", "command": "echo ok", "reason": "test invalid platform",
		"platform": "plan9",
	})
	require.NoError(t, err)
	result, ok := out.(map[string]any)
	require.True(t, ok)
	errorPayload, ok := result["error"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, "bad_request", errorPayload["kind"])
	require.Equal(t, "platform must be auto, posix, or windows", errorPayload["message"])
}

func TestHandleExecProjectRejectsUnknownProjectBeforeExec(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		t.Fatal("exec called for an unknown project")
		return nil, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{"project": "missing", "command": "echo ok", "reason": "test missing profile"})
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Contains(t, js, `unknown project \"missing\"`)
}

func TestHandleExecProjectRejectsRemovedServerBeforeExec(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	cfg.Projects["project_ajie"].Server = "removed"
	require.NoError(t, config.Save(cfgPath, cfg))

	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		t.Fatal("exec called for a project whose server was removed")
		return nil, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{"project": "project_ajie", "command": "echo ok", "reason": "test removed server"})
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Contains(t, js, `project \"project_ajie\" references unknown server \"removed\"`)
}

func TestHandleExecProjectRequiresCommand(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		t.Fatal("exec called without a command")
		return nil, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{"project": "project_ajie", "reason": "test missing command"})
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Contains(t, js, "command is required")
}

func TestHandleExecProjectRequiresReason(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		t.Fatal("exec called without a reason")
		return nil, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{"project": "project_ajie", "command": "echo ok"})
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Contains(t, js, `non-empty \"reason\" argument is required`)
}

func TestHandleExecProjectRejectsMissingRemoteRuns(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	cfg.Projects["project_ajie"].RemoteRuns = ""
	require.NoError(t, config.Save(cfgPath, cfg))

	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		t.Fatal("exec called without a configured remote_runs path")
		return nil, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{
		"project": "project_ajie", "command": "echo ok", "reason": "test missing runs", "workdir": "runs",
	})
	require.NoError(t, err)
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Contains(t, js, "remote_runs is not configured")
}

func TestHandleExecProjectBlocksDangerousPowerShellCommandBeforeEncoding(t *testing.T) {
	cfgPath, auditPath := writeExecProjectTestConfig(t)
	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	called := false
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		called = true
		return map[string]any{"exit": 0}, nil
	}

	out, err := handleExecProject(context.Background(), Deps{
		ConfigPath: cfgPath, AuditPath: auditPath,
	}, map[string]any{
		"project": "project_ajie", "command": "rm -rf /", "reason": "verify project safety",
	})
	require.NoError(t, err)
	require.False(t, called, "dangerous original command must be blocked before PowerShell encoding")
	js, err := jsonResult(out)
	require.NoError(t, err)
	require.Contains(t, js, "dangerous command blocked")
	auditBytes, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.Contains(t, string(auditBytes), "[project:project_ajie] verify project safety")
}
