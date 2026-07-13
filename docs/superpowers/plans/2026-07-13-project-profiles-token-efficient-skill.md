# Project Profiles and Token-Efficient Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic project profiles and project-scoped execution, repair the Windows detached-log contract, and reduce default skill context without changing any existing sshm tool behavior.

**Architecture:** Extend the additive TOML schema with a separate project map, expose two read and two write/project-exec MCP tools, and reuse the existing `handleExec` safety path through platform-correct workdir wrappers. Keep the core skill below 500 words and route platform/project/onboarding details to conditional references. Parse concrete Windows detach metadata and make log tailing platform-aware.

**Tech Stack:** Go 1.25, BurntSushi TOML, mark3labs mcp-go, testify, Markdown Claude/Codex skill resources.

## Global Constraints

- Existing TOML version-2 files load without manual migration and upgrade only on an explicit save.
- Every current CLI and MCP tool keeps its name, arguments, and return behavior.
- Project profiles are optional for server-only workflows and never guess missing paths.
- Existing masking, safety filter, host-key verification, auditing, and required `reason` behavior remain active.
- POSIX and native Windows remotes are first-class targets.
- Add no third-party dependency.
- Register no more than four new MCP tools: `list_projects`, `get_project`, `upsert_project`, and `exec_project`.
- Core `SKILL.md` contains at most 500 whitespace-delimited words; detailed references load only for their routed workflow.
- Binary, plugin manifest, and marketplace versions must match at `0.6.0`.

---

### Task 1: Version-3 project configuration model

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/load.go`
- Modify: `internal/config/load_test.go`

**Interfaces:**
- Produces: `config.Project`, `Config.Projects map[string]*Project`, `CurrentVersion == 3`.
- Produces: `Load` always returns non-nil `Servers` and `Projects`; `Save` upgrades lower versions to 3.

- [ ] **Step 1: Write failing configuration tests**

```go
func TestLoadV2InitializesProjectsWithoutImplicitMigration(t *testing.T) {
    p := filepath.Join(t.TempDir(), "config.toml")
    require.NoError(t, os.WriteFile(p, []byte("version = 2\n[servers]\n"), 0o600))
    cfg, err := Load(p)
    require.NoError(t, err)
    require.Equal(t, 2, cfg.Version)
    require.NotNil(t, cfg.Projects)
}

func TestProjectRoundTripAndSaveUpgrade(t *testing.T) {
    p := filepath.Join(t.TempDir(), "config.toml")
    cfg := New()
    cfg.Version = 2
    cfg.Projects["project_ajie"] = &Project{
        Server: "pc-e5", RemoteWorkspace: `C:\sshm\workspaces\project_ajie`,
        ArtifactPath: `C:\sshm\artifacts\project_ajie\latest\ajie_publish_tool.exe`,
        Shell: "powershell", BuildCommand: "python build.py onefile",
    }
    require.NoError(t, Save(p, cfg))
    got, err := Load(p)
    require.NoError(t, err)
    require.Equal(t, CurrentVersion, got.Version)
    require.Equal(t, cfg.Projects["project_ajie"], got.Projects["project_ajie"])
}
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `go test ./internal/config -run 'TestLoadV2InitializesProjects|TestProjectRoundTrip' -v`

Expected: compile failure because `Project` and `Config.Projects` do not exist.

- [ ] **Step 3: Implement the minimal schema**

```go
const CurrentVersion = 3

type Project struct {
    Server           string `toml:"server"`
    LocalRoot        string `toml:"local_root,omitempty"`
    RemoteWorkspace  string `toml:"remote_workspace"`
    RemoteRuns       string `toml:"remote_runs,omitempty"`
    ArtifactPath     string `toml:"artifact_path"`
    LocalArtifactDir string `toml:"local_artifact_dir,omitempty"`
    Shell            string `toml:"shell,omitempty"`
    BuildCommand     string `toml:"build_command,omitempty"`
    VerifyCommand    string `toml:"verify_command,omitempty"`
}
```

Add `Projects map[string]*Project` to `Config`, initialize it in `New` and
`Load`, and make `Save` set `cfg.Version = CurrentVersion` whenever the loaded
version is lower.

- [ ] **Step 4: Verify GREEN**

Run: `go test ./internal/config -v`

Expected: all config tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/load.go internal/config/load_test.go
git commit -m "feat(config): add project profiles"
```

---

### Task 2: Project profile MCP read/write tools

**Files:**
- Create: `internal/mcp/tools_project.go`
- Create: `internal/mcp/tools_project_test.go`
- Modify: `internal/mcp/server.go`
- Modify: `internal/mcp/server_test.go`

**Interfaces:**
- Consumes: `config.Project` and `Config.Projects` from Task 1.
- Produces: `handleListProjects`, `handleGetProject`, `handleUpsertProject`.
- Produces: `registerProjectReadTools` and `registerProjectWriteTools`.

- [ ] **Step 1: Write failing handler and registration tests**

Add this helper and these exact tests (imports include `context`, `os`,
`path/filepath`, `strings`, `config`, and `require`):

```go
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
```

Extend registration assertions in this task so read-only mode includes
`list_projects/get_project` and write mode additionally includes
`upsert_project`. Task 3 adds the separate `exec_project` expectation only after
that handler exists.

- [ ] **Step 2: Run tests and confirm RED**

Run: `go test ./internal/mcp -run 'Test(ListProjects|GetProject|UpsertProject|NewServer)' -v`

Expected: compile failure for missing project handlers.

- [ ] **Step 3: Implement lookup and partial updates**

Validate names with `^[a-z0-9][a-z0-9._-]*$` and shell with:

```go
func validProjectShell(v string) bool {
    switch v { case "", "auto", "posix", "powershell", "cmd": return true }
    return false
}
```

Require `server`, `remote_workspace`, and `artifact_path` on create and reject
unknown server aliases. Preserve absent update fields and clear explicitly empty
optional fields using map-key presence:

```go
func assignString(args map[string]any, key string, dst *string) {
    if raw, present := args[key]; present {
        if value, ok := raw.(string); ok { *dst = value }
    }
}
```

Audit with `Tool: "upsert_project"`, the resolved server alias, and a result
containing the project name.

- [ ] **Step 4: Register the three tools**

Register `list_projects/get_project` regardless of `AllowWrite` and
`upsert_project` only with writes enabled. Keep schemas compact.

- [ ] **Step 5: Verify GREEN**

Run: `go test ./internal/mcp -run 'Test(ListProjects|GetProject|UpsertProject|NewServer)' -v`

Expected: selected tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/mcp/tools_project.go internal/mcp/tools_project_test.go internal/mcp/server.go internal/mcp/server_test.go
git commit -m "feat(mcp): manage project profiles"
```

---

### Task 3: Safe project-scoped execution

**Files:**
- Modify: `internal/mcp/tools_project.go`
- Modify: `internal/mcp/tools_project_test.go`
- Modify: `internal/mcp/server.go`
- Modify: `internal/mcp/server_test.go`

**Interfaces:**
- Consumes: `handleExec`, `shellQuoteArg`, `config.Project`.
- Produces: `projectWorkdir`, `resolveProjectShell`, `wrapProjectCommand`, and `handleExecProject`.

- [ ] **Step 1: Write failing pure-function tests**

```go
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
```

Also test NUL/newline rejection, quote rejection for cmd paths,
`workspace/runs/artifact_parent` selection on POSIX and Windows, and auto shell
resolution (`C:\...` or UNC to PowerShell; otherwise POSIX).

- [ ] **Step 2: Run pure tests and confirm RED**

Run: `go test ./internal/mcp -run 'Test(WrapProjectCommand|ProjectWorkdir|ResolveProjectShell)' -v`

Expected: compile failure for missing helpers.

- [ ] **Step 3: Implement wrappers**

Encode PowerShell scripts as UTF-16LE base64 with these helpers:

```go
func utf16LE(s string) []byte {
    words := utf16.Encode([]rune(s))
    out := make([]byte, len(words)*2)
    for i, word := range words {
        binary.LittleEndian.PutUint16(out[i*2:], word)
    }
    return out
}

script := "Set-Location -LiteralPath " + powershellSingleQuote(workdir) +
    "; if (-not $?) { exit 1 }; " + command
encoded := base64.StdEncoding.EncodeToString(utf16LE(script))
return "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded, nil
```

Use `path.Dir` for POSIX artifact parents and the last slash/backslash for
Windows; never use local `filepath.Dir` for remote paths.

- [ ] **Step 4: Write failing handler tests**

Cover missing project, removed server, missing command, and missing `RemoteRuns`.
Add `var runProjectExec = handleExec` as a test seam. Assert the forwarded alias,
wrapped command, timeout/detach/platform, and reason prefix
`[project:project_ajie]`.
Assert the returned map adds `project`, `alias`, `workdir`, and `shell` without
removing existing exec fields.

- [ ] **Step 5: Run handler tests and confirm RED**

Run: `go test ./internal/mcp -run 'TestHandleExecProject' -v`

Expected: handler or registration missing.

- [ ] **Step 6: Implement and register `exec_project`**

Required fields are `project`, `command`, and `reason`; optional fields are
`workdir`, `unsafe`, `timeout_seconds`, `detach`, and `platform`. Register only
with writes enabled and route through `runProjectExec`.

- [ ] **Step 7: Verify GREEN**

Run: `go test ./internal/mcp -v`

Expected: all MCP tests pass.

- [ ] **Step 8: Commit**

```bash
git add internal/mcp/tools_project.go internal/mcp/tools_project_test.go internal/mcp/server.go internal/mcp/server_test.go
git commit -m "feat(mcp): execute commands in project workspaces"
```

---

### Task 4: Cross-platform detached metadata and log tailing

**Files:**
- Modify: `internal/mcp/tools_exec.go`
- Delete: `internal/mcp/detach_windows_test.go`
- Create: `internal/mcp/detach_test.go`
- Modify: `internal/mcp/tools_ops.go`
- Modify: `internal/mcp/tools_ops_test.go`

**Interfaces:**
- Produces: `parseDetachMetadata(stdout string) (pid int, logPath string)`.
- Produces: `tailCommand(platform, path string, lines int) string`.
- Extends: `tail_logs` with optional `platform=auto|posix|windows`.

- [ ] **Step 1: Write failing detach metadata tests**

```go
func TestParseDetachMetadata(t *testing.T) {
    pid, logPath := parseDetachMetadata("pid=4321\r\nlog=C:\\Users\\ming\\AppData\\Local\\Temp\\sshm.log\r\n")
    require.Equal(t, 4321, pid)
    require.Equal(t, `C:\Users\ming\AppData\Local\Temp\sshm.log`, logPath)
}
```

Add a result-builder test showing a Windows detached result uses the concrete
parsed log path and includes `pid`.

- [ ] **Step 2: Run detach tests and confirm RED**

Run: `go test ./internal/mcp -run 'Test(ParseDetachMetadata|BuildDetachLauncher)' -v`

Expected: compile failure for `parseDetachMetadata`.

- [ ] **Step 3: Parse launcher stdout into results**

Parse trimmed `pid=` and `log=` lines. In `runDetached`, replace the Windows
template path with parsed output and add `pid` when positive. If Windows output
lacks `log=`, return a structured exec error. Preserve POSIX behavior.

- [ ] **Step 4: Write failing platform-tail tests**

```go
func decodePowerShellCommand(t *testing.T, command string) string {
    t.Helper()
    fields := strings.Fields(command)
    require.Contains(t, command, "powershell.exe -NoProfile -NonInteractive -EncodedCommand ")
    raw, err := base64.StdEncoding.DecodeString(fields[len(fields)-1])
    require.NoError(t, err)
    require.Zero(t, len(raw)%2)
    words := make([]uint16, len(raw)/2)
    for i := range words {
        words[i] = binary.LittleEndian.Uint16(raw[i*2:])
    }
    return string(utf16.Decode(words))
}

func TestTailCommandPOSIX(t *testing.T) {
    require.Equal(t, "tail -n 25 '/tmp/a b.log'", tailCommand("posix", "/tmp/a b.log", 25))
}

func TestTailCommandWindows(t *testing.T) {
    got := tailCommand("windows", `C:\Temp\a b.log`, 25)
    script := decodePowerShellCommand(t, got)
    require.Contains(t, script, "Get-Content -LiteralPath")
    require.Contains(t, script, "-Tail 25")
}
```

- [ ] **Step 5: Run tail tests and confirm RED**

Run: `go test ./internal/mcp -run 'TestTailCommand' -v`

Expected: compile failure for `tailCommand`.

- [ ] **Step 6: Implement platform-aware `tail_logs`**

Normalize `auto` through `detectRemoteDetachPlatform(ctx, cli)`. Reject values
outside `auto|posix|windows` with `bad_request` before dialing. Generate POSIX
`tail -n` or a PowerShell encoded command containing
`Get-Content -LiteralPath 'C:\Temp\build.log' -Tail 25`. Return the resolved
platform and add the optional field to the tool schema. If the remote command
returns a non-zero exit code, return a structured `exec` error containing masked
stderr; successful return fields remain unchanged. When a Windows detached
launcher exits zero but omits `log=`, audit the partial launch and return recovery
metadata including alias, platform, stdout, and any parsed pid. Correct exec
descriptions so they no longer claim detach is POSIX-only.

- [ ] **Step 7: Verify GREEN**

Run: `go test ./internal/mcp -v`

Expected: all MCP tests pass.

- [ ] **Step 8: Commit**

```bash
git add internal/mcp/tools_exec.go internal/mcp/detach_windows_test.go internal/mcp/detach_test.go internal/mcp/tools_ops.go internal/mcp/tools_ops_test.go
git commit -m "fix(mcp): make detached logs readable on Windows"
```

---

### Task 5: Token-efficient skill and aligned versions

**Files:**
- Modify: `plugins/sshm-skill/skills/sshm-server-ops/SKILL.md`
- Modify: `plugins/sshm-skill/skills/sshm-server-ops/quick-reference.md`
- Modify: `plugins/sshm-skill/skills/sshm-server-ops/ai-patterns.md`
- Create: `plugins/sshm-skill/skills/sshm-server-ops/project-workflows.md`
- Create: `plugins/sshm-skill/skills/sshm-server-ops/onboarding.md`
- Create: `plugins/sshm-skill/skills/sshm-server-ops/skill_test.go`
- Modify: `plugins/sshm-skill/.claude-plugin/plugin.json`
- Modify: `.claude-plugin/marketplace.json`
- Modify: `internal/commands/version.go`
- Modify: `internal/commands/version_test.go`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: project tools and platform-aware `tail_logs`.
- Produces: core skill at most 500 words with conditional reference routing.
- Produces: source/plugin/marketplace version `0.6.0` and consistency test.

- [ ] **Step 1: Record documentation baseline**

Run:

```bash
wc -w -c plugins/sshm-skill/skills/sshm-server-ops/{SKILL.md,quick-reference.md,ai-patterns.md}
```

Expected baseline: core 642 words/4242 bytes; combined 1199 words/8056 bytes.

- [ ] **Step 2: Write failing skill-budget tests**

In `skill_test.go`, locate its directory with `runtime.Caller(0)`, read
`SKILL.md`, assert `len(strings.Fields(core)) <= 500`, and assert these files
exist: `project-workflows.md`, `onboarding.md`, `quick-reference.md`, and
`ai-patterns.md`. Assert core contains all four project tool names plus the
phrases `do not retry the same failed mutation blindly` and `changed host key`.

Run: `go test ./plugins/sshm-skill/skills/sshm-server-ops -v`

Expected: failure because the core exceeds 500 words and references are absent.

- [ ] **Step 3: Rewrite with progressive disclosure**

Keep the frontmatter trigger broad enough for server work, deployments, remote
project builds, Windows EXE packaging, and artifact transfer. Core content:

- tool selection and one `check_ssh` preflight;
- profile reuse and no path guessing;
- safety invariants and read-only diagnostic fallback;
- exact conditional routing that says to read only the relevant file.

Move onboarding to `onboarding.md`. Put stable workspace/run/artifact rules,
Windows long-timeout fallback, SHA-256, freshness, and smoke checks in
`project-workflows.md`. Make `ai-patterns.md` a compact index without duplicating
the references. Update `quick-reference.md` for project tools and
`tail_logs.platform`.

- [ ] **Step 4: Verify budget GREEN and record new sizes**

Run:

```bash
go test ./plugins/sshm-skill/skills/sshm-server-ops -v
wc -w -c plugins/sshm-skill/skills/sshm-server-ops/{SKILL.md,project-workflows.md,onboarding.md,quick-reference.md,ai-patterns.md}
```

Expected: test passes and core is at most 500 words. Compare core and the common
project path (`SKILL.md + project-workflows.md`) with the old 1199-word load.

- [ ] **Step 5: Write failing version-consistency test**

Extend `internal/commands/version_test.go` to parse both JSON manifests and
assert `Version`, marketplace top-level version, marketplace plugin version, and
plugin manifest version are all exactly `0.6.0`.

Run: `go test ./internal/commands -run TestDeclaredVersionsMatch -v`

Expected: failure because declarations are 0.5.0/0.5.1.

- [ ] **Step 6: Align version and release documentation**

Set all declarations to `0.6.0`. Add a changelog section dated 2026-07-13 for
project profiles, project exec, cross-platform detached logs, compatibility, and
skill token reduction. Mark project profiles shipped in README and move SSH
config import/export and tag filtering to 0.7.

- [ ] **Step 7: Verify GREEN**

Run: `go test ./internal/commands ./plugins/sshm-skill/skills/sshm-server-ops -v`

Expected: selected packages pass.

- [ ] **Step 8: Commit**

```bash
git add .claude-plugin/marketplace.json CHANGELOG.md README.md internal/commands/version.go internal/commands/version_test.go plugins/sshm-skill
git commit -m "docs(skill): add project workflows with lower token cost"
```

---

### Task 6: Full compatibility and cross-platform verification

**Files:**
- Modify only files required by a concrete failure found below.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: verified release candidate with no uncommitted fixes.

- [ ] **Step 1: Run formatting and diff checks**

Run:

```bash
gofmt -w internal/config/*.go internal/mcp/*.go internal/commands/*.go plugins/sshm-skill/skills/sshm-server-ops/skill_test.go
git diff --check
```

Expected: no formatting or whitespace errors.

- [ ] **Step 2: Run complete suite**

Run: `go test ./...`

Expected: every package passes with zero failures.

- [ ] **Step 3: Run race-sensitive packages**

Run: `go test -race ./internal/config ./internal/mcp`

Expected: both packages pass with no reported race.

- [ ] **Step 4: Cross-build supported systems**

Run:

```bash
GOOS=linux GOARCH=amd64 go build -o /tmp/sshm-linux ./cmd/sshm
GOOS=darwin GOARCH=arm64 go build -o /tmp/sshm-darwin ./cmd/sshm
GOOS=windows GOARCH=amd64 go build -o /tmp/sshm-windows.exe ./cmd/sshm
```

Expected: all builds exit 0; outputs stay outside the repository.

- [ ] **Step 5: Verify measurements and requirements**

Run Task 5 word/byte measurement, review the design line by line, and inspect
registered names. Expected: core at most 500 words, exactly four new project
tools, old tools unchanged, and all versions aligned.

- [ ] **Step 6: Commit verification fixes if needed**

If a concrete failure required changes, stage only those reviewed files and
commit `fix: address project profile verification findings`. If no file changed,
do not create an empty commit.
