package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
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

func TestProjectReadHandlersRejectHandEditedCredentialsWithoutLeakingSecret(t *testing.T) {
	tests := []struct {
		name          string
		projectFields string
		field         string
		secret        string
		handler       func(context.Context, Deps, map[string]any) (any, error)
		args          map[string]any
	}{
		{name: "list URI password", projectFields: "remote_workspace = \"https://alice:list-load-secret@example.com/repo\"\n", field: "remote_workspace", secret: "list-load-secret", handler: handleListProjects},
		{name: "get curl password", projectFields: "remote_workspace = \"/srv/app\"\nbuild_command = \"curl -u alice:get-load-secret https://example.com\"\n", field: "build_command", secret: "get-load-secret", handler: handleGetProject, args: map[string]any{"project": "manual"}},
		{name: "exec sshpass password", projectFields: "remote_workspace = \"/srv/app\"\nverify_command = \"sshpass -p exec-load-secret ssh example.com\"\n", field: "verify_command", secret: "exec-load-secret", handler: handleExecProject, args: map[string]any{"project": "manual", "command": "echo ok", "reason": "test unsafe manual config"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			data := "version = 3\n[servers.prod]\nhost = \"example.com\"\nport = 22\nuser = \"builder\"\nauth = \"key\"\n[projects.manual]\nserver = \"prod\"\nartifact_path = \"/srv/app.tgz\"\n" + tt.projectFields
			require.NoError(t, os.WriteFile(cfgPath, []byte(data), 0o600))

			oldRunProjectExec := runProjectExec
			t.Cleanup(func() { runProjectExec = oldRunProjectExec })
			execCalled := false
			runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
				execCalled = true
				return map[string]any{"exit": 0}, nil
			}

			out, err := tt.handler(context.Background(), Deps{ConfigPath: cfgPath}, tt.args)
			require.NoError(t, err)
			require.False(t, execCalled, "exec_project must stop before remote execution")
			js, err := jsonResult(out)
			require.NoError(t, err)
			require.NotContains(t, js, tt.secret)
			result, ok := out.(map[string]any)
			require.True(t, ok)
			errorPayload, ok := result["error"].(map[string]string)
			require.True(t, ok)
			require.Equal(t, "config", errorPayload["kind"])
			require.Contains(t, errorPayload["message"], tt.field)
			require.NotContains(t, errorPayload["message"], tt.secret)
		})
	}
}

func TestRegisteredProjectToolsPreserveValidatedProfilesExactly(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	data := `version = 3
[servers."10.0.0.5"]
host = "example.com"
port = 22
user = "builder"
auth = "key"

[projects.safe]
server = "10.0.0.5"
remote_workspace = '\\10.0.0.5\share'
artifact_path = '\\10.0.0.5\share\app.exe'
build_command = 'TOKEN_FILE=/run/secrets/token API_KEY_PATH=/run/secrets/api-key TOKEN=$TOKEN mysql -p$MYSQL_PASSWORD database'
verify_command = 'sshpass -p $SSHPASS ssh example.com && curl -u alice:$CURL_PASSWORD http://10.0.0.5/health'
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(data), 0o600))

	oldRunProjectExec := runProjectExec
	t.Cleanup(func() { runProjectExec = oldRunProjectExec })
	runProjectExec = func(_ context.Context, _ Deps, _ map[string]any) (any, error) {
		return map[string]any{"exit": 0, "stdout": "ok", "stderr": ""}, nil
	}

	s, _ := NewServer(Deps{ConfigPath: cfgPath, AllowWrite: true})
	call := func(name string, args map[string]any) string {
		t.Helper()
		tool := s.GetTool(name)
		require.NotNil(t, tool)
		result, err := tool.Handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args}})
		require.NoError(t, err)
		require.Len(t, result.Content, 1)
		content, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		return content.Text
	}

	getText := call("get_project", map[string]any{"project": "safe"})
	var profile map[string]any
	require.NoError(t, json.Unmarshal([]byte(getText), &profile))
	require.Equal(t, `\\10.0.0.5\share`, profile["remote_workspace"])
	require.Equal(t, "TOKEN_FILE=/run/secrets/token API_KEY_PATH=/run/secrets/api-key TOKEN=$TOKEN mysql -p$MYSQL_PASSWORD database", profile["build_command"])
	require.Equal(t, "sshpass -p $SSHPASS ssh example.com && curl -u alice:$CURL_PASSWORD http://10.0.0.5/health", profile["verify_command"])

	listText := call("list_projects", nil)
	var listResult struct {
		Projects []struct {
			Server          string `json:"server"`
			RemoteWorkspace string `json:"remote_workspace"`
		} `json:"projects"`
	}
	require.NoError(t, json.Unmarshal([]byte(listText), &listResult))
	require.Len(t, listResult.Projects, 1)
	require.Equal(t, "10.0.0.5", listResult.Projects[0].Server)
	require.Equal(t, `\\10.0.0.5\share`, listResult.Projects[0].RemoteWorkspace)

	upsertText := call("upsert_project", map[string]any{
		"project": "safe", "reason": "verify exact registered upsert response",
	})
	var upsertResult map[string]any
	require.NoError(t, json.Unmarshal([]byte(upsertText), &upsertResult))
	require.Equal(t, "10.0.0.5", upsertResult["server"])

	execText := call("exec_project", map[string]any{"project": "safe", "command": "echo ok", "reason": "test exact project serialization"})
	var execResult map[string]any
	require.NoError(t, json.Unmarshal([]byte(execText), &execResult))
	require.Equal(t, `\\10.0.0.5\share`, execResult["workdir"])
	require.Equal(t, "10.0.0.5", execResult["alias"])

	githubToken := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	errorText := call("get_project", map[string]any{"project": githubToken})
	require.NotContains(t, errorText, githubToken)
	require.Contains(t, errorText, "***")
	var maskedError map[string]any
	require.NoError(t, json.Unmarshal([]byte(errorText), &maskedError))

	assignmentErrorText := call("get_project", map[string]any{"project": "TOKEN=literal-secret"})
	require.NotContains(t, assignmentErrorText, "literal-secret")
	require.NoError(t, json.Unmarshal([]byte(assignmentErrorText), &maskedError))
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

func TestUpsertProjectRepairsInvalidExistingProfile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	data := `version = 3
[servers.pc-e5]
host = "example.com"
port = 22
user = "builder"
auth = "key"

[projects.a]
server = "pc-e5"
remote_workspace = "C:\\sshm\\workspaces\\a"
artifact_path = "C:\\sshm\\artifacts\\a.exe"
shell = "invalid-shell"
build_command = "curl -u alice:repair-secret https://example.com"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(data), 0o600))

	before, err := config.Load(cfgPath)
	require.NoError(t, err, "unsafe optional profile must remain loadable for repair")
	require.Error(t, config.ValidateProjects(before))

	out, err := handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
		"project":       "a",
		"shell":         "powershell",
		"build_command": "",
		"reason":        "repair hand-edited project profile",
	})
	require.NoError(t, err)
	result, ok := out.(map[string]any)
	require.True(t, ok)
	require.NotContains(t, result, "error")
	require.NotContains(t, result, "repair-secret")

	after, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, config.ValidateProjects(after))
	require.Equal(t, "powershell", after.Projects["a"].Shell)
	require.Empty(t, after.Projects["a"].BuildCommand)
}

func TestUpsertProjectRejectsCredentialFieldsWithoutModifyingDisk(t *testing.T) {
	githubToken := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	fields := []struct {
		caseName     string
		name         string
		value        string
		secretNeedle string
	}{
		{caseName: "PEM local root", name: "local_root", value: "-----BEGIN PRIVATE KEY-----\nprivate-data\n-----END PRIVATE KEY-----", secretNeedle: "private-data"},
		{caseName: "URI workspace password", name: "remote_workspace", value: "sftp://builder:workspace-secret@example.com/work", secretNeedle: "workspace-secret"},
		{caseName: "token server", name: "server", value: githubToken, secretNeedle: githubToken},
		{caseName: "token shell", name: "shell", value: githubToken, secretNeedle: githubToken},
		{caseName: "AWS remote runs", name: "remote_runs", value: "AKIAIOSFODNN7EXAMPLE", secretNeedle: "AKIAIOSFODNN7EXAMPLE"},
		{caseName: "Slack artifact path", name: "artifact_path", value: "/tmp/xoxb-1234567890-abcdefghij", secretNeedle: "xoxb-1234567890-abcdefghij"},
		{caseName: "JWT local artifact", name: "local_artifact_dir", value: "eyJhbGciOiJIUzI1NiJ9.payload.signature", secretNeedle: "eyJhbGciOiJIUzI1NiJ9.payload.signature"},
		{caseName: "secret build flag", name: "build_command", value: "builder --client-secret build-secret", secretNeedle: "build-secret"},
		{caseName: "colon verify token", name: "verify_command", value: "token: verify-secret", secretNeedle: "verify-secret"},
		{caseName: "concatenated password", name: "build_command", value: "DBPASSWORD=db-secret make", secretNeedle: "db-secret"},
		{caseName: "concatenated token", name: "verify_command", value: "DEPLOYTOKEN=deploy-secret verify", secretNeedle: "deploy-secret"},
		{caseName: "terminal key", name: "local_root", value: "SIGNING_KEY=signing-secret", secretNeedle: "signing-secret"},
		{caseName: "mysql short password", name: "build_command", value: "mysql -uroot -pdb-secret database", secretNeedle: "db-secret"},
		{caseName: "sshpass separated password", name: "build_command", value: "sshpass -p sshpass-secret ssh example.com", secretNeedle: "sshpass-secret"},
		{caseName: "docker login separated password", name: "build_command", value: "docker login -u alice -p docker-secret", secretNeedle: "docker-secret"},
		{caseName: "curl user password", name: "verify_command", value: "curl -u alice:curl-secret https://example.com", secretNeedle: "curl-secret"},
		{caseName: "multiline mysql short password", name: "build_command", value: "echo preflight\nmysql -uroot -pmultiline-secret database", secretNeedle: "multiline-secret"},
		{caseName: "subshell mysql short password", name: "verify_command", value: "(mysql -uroot -psubshell-secret database)", secretNeedle: "subshell-secret"},
		{caseName: "concatenated pass", name: "build_command", value: "DBPASS=dbpass-secret deploy", secretNeedle: "dbpass-secret"},
		{caseName: "hardcoded env default", name: "verify_command", value: "TOKEN=${TOKEN:-default-secret} verify", secretNeedle: "default-secret"},
	}

	for _, field := range fields {
		t.Run(field.caseName, func(t *testing.T) {
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

func TestUpsertProjectRejectsTokenShapedNameWithoutModifyingDisk(t *testing.T) {
	githubToken := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	cfgPath, auditPath := writeProjectTestConfig(t)
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	out, err := handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
		"project": githubToken, "server": "pc-e5", "remote_workspace": "/srv/app",
		"artifact_path": "/srv/app.tgz", "reason": "test token project name",
	})
	require.NoError(t, err)
	result, ok := out.(map[string]any)
	require.True(t, ok)
	errorPayload, ok := result["error"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, "bad_request", errorPayload["kind"])
	require.Contains(t, errorPayload["message"], "project name")
	require.NotContains(t, errorPayload["message"], githubToken)

	after, readErr := os.ReadFile(cfgPath)
	require.NoError(t, readErr)
	require.Equal(t, before, after)
}

func TestUpsertProjectRejectsServerControlCharactersWithoutLeakingValue(t *testing.T) {
	cfgPath, auditPath := writeProjectTestConfig(t)
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	out, err := handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
		"project": "a", "server": "prod\nsecret-tail", "reason": "test invalid server control characters",
	})
	require.NoError(t, err)
	result := out.(map[string]any)
	errorPayload := result["error"].(map[string]string)
	require.Equal(t, "bad_request", errorPayload["kind"])
	require.Contains(t, errorPayload["message"], "server")
	require.NotContains(t, errorPayload["message"], "secret-tail")

	after, readErr := os.ReadFile(cfgPath)
	require.NoError(t, readErr)
	require.Equal(t, before, after)
}

func TestUpsertProjectAllowsBenignCredentialLikeValues(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
		get   func(*config.Project) string
	}{
		{name: "Go parallel flag", field: "build_command", value: "go test -parallel=4 ./...", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "port flag", field: "verify_command", value: "app -port=8080", get: func(p *config.Project) string { return p.VerifyCommand }},
		{name: "profile flag", field: "verify_command", value: "tool -profile=release", get: func(p *config.Project) string { return p.VerifyCommand }},
		{name: "mysql password prompt", field: "build_command", value: "mysql -uroot -p database", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "sshpass env password", field: "verify_command", value: "sshpass -p $SSHPASS ssh example.com", get: func(p *config.Project) string { return p.VerifyCommand }},
		{name: "pass suffix words", field: "build_command", value: "COMPASS=true BYPASS=false build", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "ambiguous bare key", field: "build_command", value: "KEY=bare-key-secret build", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "Docker password stdin", field: "build_command", value: "docker login --password-stdin registry.example.com", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "credential file references", field: "build_command", value: "TOKEN_FILE=/run/secrets/token deploy --secret-file /run/secrets/token", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "Docker BuildKit source secret", field: "build_command", value: "docker build --secret id=npmrc,src=/run/secrets/npmrc .", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "Docker BuildKit environment secret", field: "build_command", value: "docker build --secret id=npmrc,env=NPM_TOKEN .", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "curl env password", field: "verify_command", value: "curl -u alice:$CURL_PASSWORD https://example.com", get: func(p *config.Project) string { return p.VerifyCommand }},
		{name: "API key path", field: "build_command", value: "API_KEY_PATH=/tmp/api-key build", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "HTTP username", field: "local_root", value: "https://alice@example.com/source", get: func(p *config.Project) string { return p.LocalRoot }},
		{name: "braced PowerShell env", field: "build_command", value: "TOKEN=${env:TOKEN} deploy", get: func(p *config.Project) string { return p.BuildCommand }},
		{name: "required POSIX env", field: "verify_command", value: "TOKEN=${TOKEN:?required} verify", get: func(p *config.Project) string { return p.VerifyCommand }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgPath, auditPath := writeProjectTestConfig(t)
			out, err := handleUpsertProject(Deps{ConfigPath: cfgPath, AuditPath: auditPath}, map[string]any{
				"project": "a", "reason": "test benign credential-like value", tt.field: tt.value,
			})
			require.NoError(t, err)
			result, ok := out.(map[string]any)
			require.True(t, ok)
			require.NotContains(t, result, "error")

			cfg, err := config.Load(cfgPath)
			require.NoError(t, err)
			require.Equal(t, tt.value, tt.get(cfg.Projects["a"]))
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
