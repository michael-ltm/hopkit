package mcp

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
)

var projectNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func isWindowsRemotePath(remotePath string) bool {
	if strings.HasPrefix(remotePath, `\\`) {
		return true
	}
	if len(remotePath) < 3 || remotePath[1] != ':' || (remotePath[2] != '\\' && remotePath[2] != '/') {
		return false
	}
	first := remotePath[0]
	return first >= 'A' && first <= 'Z' || first >= 'a' && first <= 'z'
}

func projectWorkdir(project *config.Project, selector string) (string, error) {
	if project == nil {
		return "", fmt.Errorf("project profile is missing")
	}

	var workdir string
	switch selector {
	case "", "workspace":
		workdir = project.RemoteWorkspace
	case "runs":
		workdir = project.RemoteRuns
		if workdir == "" {
			return "", fmt.Errorf("remote_runs is not configured")
		}
	case "artifact_parent":
		if project.ArtifactPath == "" {
			return "", fmt.Errorf("artifact_path is not configured")
		}
		if isWindowsRemotePath(project.ArtifactPath) {
			lastSeparator := strings.LastIndexAny(project.ArtifactPath, `/\`)
			if lastSeparator < 0 {
				return "", fmt.Errorf("artifact_path has no parent directory")
			}
			if lastSeparator == 2 && project.ArtifactPath[1] == ':' {
				workdir = project.ArtifactPath[:lastSeparator+1]
			} else {
				workdir = project.ArtifactPath[:lastSeparator]
			}
		} else {
			workdir = path.Dir(project.ArtifactPath)
		}
	default:
		return "", fmt.Errorf("workdir must be workspace, runs, or artifact_parent")
	}
	if workdir == "" {
		return "", fmt.Errorf("selected workdir is not configured")
	}
	return workdir, nil
}

func resolveProjectShell(configured, workdir string) (string, error) {
	switch configured {
	case "", "auto":
		if isWindowsRemotePath(workdir) {
			return "powershell", nil
		}
		return "posix", nil
	case "posix", "powershell", "cmd":
		return configured, nil
	default:
		return "", fmt.Errorf("unsupported project shell %q", configured)
	}
}

func wrapProjectCommand(shell, workdir, command string) (string, error) {
	if workdir == "" {
		return "", fmt.Errorf("workdir is required")
	}
	if strings.ContainsAny(workdir, "\x00\r\n") {
		return "", fmt.Errorf("workdir must not contain NUL or newline characters")
	}

	switch shell {
	case "posix":
		return "cd " + shellQuoteArg(workdir) + " && " + command, nil
	case "powershell":
		script := "Set-Location -LiteralPath " + powershellSingleQuote(workdir) +
			"; if (-not $?) { exit 1 }; " + command
		return powershellEncodedCommand(script), nil
	case "cmd":
		if strings.Contains(workdir, `"`) {
			return "", fmt.Errorf("cmd workdir must not contain double quotes")
		}
		return fmt.Sprintf(`cmd.exe /d /s /c "cd /d ""%s"" && %s"`, workdir, command), nil
	default:
		return "", fmt.Errorf("unsupported project shell %q", shell)
	}
}

var runProjectExec = handleExec

func unknownProjectResult(name string, projects map[string]*config.Project) map[string]any {
	available := make([]string, 0, len(projects))
	for candidate, profile := range projects {
		if profile != nil {
			available = append(available, candidate)
		}
	}
	sort.Strings(available)
	message := fmt.Sprintf("unknown project %q", name)
	if len(available) > 0 {
		message += "; available projects: " + strings.Join(available, ", ")
	}
	return errResult("not_found", message)
}

func handleExecProject(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	name := strArg(args, "project")
	if name == "" {
		return errResult("bad_request", "project is required"), nil
	}
	command := strArg(args, "command")
	if command == "" {
		return errResult("bad_request", "command is required"), nil
	}
	platform := strings.ToLower(strings.TrimSpace(strArg(args, "platform")))
	switch platform {
	case "", "auto", "posix", "windows":
	default:
		return errResult("bad_request", "platform must be auto, posix, or windows"), nil
	}

	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	project, ok := cfg.Projects[name]
	if !ok || project == nil {
		return unknownProjectResult(name, cfg.Projects), nil
	}
	if _, ok := cfg.Servers[project.Server]; !ok {
		return errResult("config", fmt.Sprintf(
			"project %q references unknown server %q", name, project.Server)), nil
	}

	workdir, err := projectWorkdir(project, strArg(args, "workdir"))
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	shell, err := resolveProjectShell(project.Shell, workdir)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	projectReason := fmt.Sprintf("[project:%s] %s", name, reason)
	unsafe, _ := args["unsafe"].(bool)
	if !unsafe {
		if hit, why := safety.IsDangerous(command); hit {
			audit(deps, safety.Entry{
				Tool: "exec", Alias: project.Server, Reason: projectReason,
				Result: "blocked: dangerous command",
			})
			return errResult("dangerous", fmt.Sprintf(
				"dangerous command blocked (%s); pass unsafe=true to override", why)), nil
		}
	}
	wrappedCommand, err := wrapProjectCommand(shell, workdir, command)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}

	execArgs := map[string]any{
		"alias": project.Server, "command": wrappedCommand,
		"reason": projectReason,
	}
	for _, key := range []string{"unsafe", "timeout_seconds", "detach"} {
		if value, present := args[key]; present {
			execArgs[key] = value
		}
	}
	if platform != "" {
		execArgs["platform"] = platform
	}
	detach, _ := args["detach"].(bool)
	if detach && (strings.TrimSpace(platform) == "" || strings.EqualFold(platform, "auto")) &&
		(shell == "powershell" || shell == "cmd") {
		execArgs["platform"] = "windows"
	}
	execResult, err := runProjectExec(ctx, deps, execArgs)
	if err != nil {
		return nil, err
	}
	result, ok := execResult.(map[string]any)
	if !ok {
		return errResult("exec", "unexpected exec result"), nil
	}

	out := make(map[string]any, len(result)+4)
	for key, value := range result {
		out[key] = value
	}
	out["project"] = name
	out["alias"] = project.Server
	out["workdir"] = workdir
	out["shell"] = shell
	return out, nil
}

func validProjectShell(v string) bool {
	switch v {
	case "", "auto", "posix", "powershell", "cmd":
		return true
	}
	return false
}

func assignString(args map[string]any, key string, dst *string) {
	if raw, present := args[key]; present {
		if value, ok := raw.(string); ok {
			*dst = value
		}
	}
}

// handleListProjects returns compact profiles sorted by project name.
func handleListProjects(_ context.Context, deps Deps, _ map[string]any) (any, error) {
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	type entry struct {
		Project         string `json:"project"`
		Server          string `json:"server"`
		Shell           string `json:"shell"`
		RemoteWorkspace string `json:"remote_workspace"`
	}
	list := make([]entry, 0, len(cfg.Projects))
	for name, project := range cfg.Projects {
		if project == nil {
			continue
		}
		list = append(list, entry{
			Project: name, Server: project.Server, Shell: project.Shell,
			RemoteWorkspace: project.RemoteWorkspace,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Project < list[j].Project })
	return map[string]any{"projects": list}, nil
}

// handleGetProject returns one complete project profile.
func handleGetProject(_ context.Context, deps Deps, args map[string]any) (any, error) {
	name := strArg(args, "project")
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	project, ok := cfg.Projects[name]
	if !ok || project == nil {
		return unknownProjectResult(name, cfg.Projects), nil
	}
	return map[string]any{
		"project":            name,
		"server":             project.Server,
		"local_root":         project.LocalRoot,
		"remote_workspace":   project.RemoteWorkspace,
		"remote_runs":        project.RemoteRuns,
		"artifact_path":      project.ArtifactPath,
		"local_artifact_dir": project.LocalArtifactDir,
		"shell":              project.Shell,
		"build_command":      project.BuildCommand,
		"verify_command":     project.VerifyCommand,
	}, nil
}

// handleUpsertProject creates or partially updates one project profile.
func handleUpsertProject(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	name := strArg(args, "project")
	if !projectNamePattern.MatchString(name) {
		return errResult("bad_request", "project must match ^[a-z0-9][a-z0-9._-]*$"), nil
	}
	if raw, present := args["shell"]; present {
		if value, ok := raw.(string); ok && !validProjectShell(value) {
			return errResult("bad_request", fmt.Sprintf("shell %q must be auto, posix, powershell, or cmd", value)), nil
		}
	}
	for _, field := range []string{
		"local_root", "remote_workspace", "remote_runs", "artifact_path",
		"local_artifact_dir", "build_command", "verify_command",
	} {
		if value, ok := args[field].(string); ok && safety.ContainsCredentialMaterial(value) {
			return errResult("bad_request", fmt.Sprintf(
				"project field %q must not contain credential material", field)), nil
		}
	}

	var (
		created        bool
		serverAlias    string
		requestKind    string
		requestMessage string
	)
	reject := func(kind, message string) error {
		requestKind, requestMessage = kind, message
		return fmt.Errorf("%s", message)
	}
	err = config.Update(deps.ConfigPath, func(cfg *config.Config) error {
		project, exists := cfg.Projects[name]
		if !exists || project == nil {
			project = &config.Project{}
			created = true
		}

		assignString(args, "server", &project.Server)
		assignString(args, "local_root", &project.LocalRoot)
		assignString(args, "remote_workspace", &project.RemoteWorkspace)
		assignString(args, "remote_runs", &project.RemoteRuns)
		assignString(args, "artifact_path", &project.ArtifactPath)
		assignString(args, "local_artifact_dir", &project.LocalArtifactDir)
		assignString(args, "shell", &project.Shell)
		assignString(args, "build_command", &project.BuildCommand)
		assignString(args, "verify_command", &project.VerifyCommand)

		if project.Server == "" {
			return reject("bad_request", "server is required")
		}
		if project.RemoteWorkspace == "" {
			return reject("bad_request", "remote_workspace is required")
		}
		if project.ArtifactPath == "" {
			return reject("bad_request", "artifact_path is required")
		}
		if _, ok := cfg.Servers[project.Server]; !ok {
			return reject("bad_request", fmt.Sprintf("unknown server %q", project.Server))
		}

		serverAlias = project.Server
		cfg.Projects[name] = project
		return nil
	})
	if requestMessage != "" {
		return errResult(requestKind, requestMessage), nil
	}
	if err != nil {
		return errResult("config", err.Error()), nil
	}

	audit(deps, safety.Entry{
		Tool: "upsert_project", Alias: serverAlias, Reason: reason,
		Result: fmt.Sprintf("project=%s", name),
	})
	return map[string]any{
		"project": name, "server": serverAlias, "created": created, "updated": !created,
	}, nil
}

func registerProjectReadTools(s *server.MCPServer, deps Deps, names []string) []string {
	add := func(tool mcp.Tool, fn func(context.Context, Deps, map[string]any) (any, error)) {
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := fn(ctx, deps, req.GetArguments())
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			js, err := jsonResult(out)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
		})
		names = append(names, tool.Name)
	}
	add(mcp.NewTool("list_projects",
		mcp.WithDescription("List compact project profiles.")), handleListProjects)
	add(mcp.NewTool("get_project",
		mcp.WithDescription("Get one complete project profile."),
		mcp.WithString("project", mcp.Required(), mcp.Description("project name"))), handleGetProject)
	return names
}

func registerProjectWriteTools(s *server.MCPServer, deps Deps, names []string) []string {
	tool := mcp.NewTool("upsert_project",
		mcp.WithDescription("Create or partially update a project profile (requires reason; audited)."),
		mcp.WithString("project", mcp.Required(), mcp.Description("project name")),
		mcp.WithString("reason", mcp.Required(), mcp.Description("why this change is being made")),
		mcp.WithString("server", mcp.Description("existing server alias")),
		mcp.WithString("local_root", mcp.Description("optional local source root")),
		mcp.WithString("remote_workspace", mcp.Description("stable remote source workspace")),
		mcp.WithString("remote_runs", mcp.Description("optional remote runs root")),
		mcp.WithString("artifact_path", mcp.Description("stable remote artifact path")),
		mcp.WithString("local_artifact_dir", mcp.Description("optional local artifact directory")),
		mcp.WithString("shell", mcp.Description("auto|posix|powershell|cmd")),
		mcp.WithString("build_command", mcp.Description("optional build command")),
		mcp.WithString("verify_command", mcp.Description("optional verification command")))
	s.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleUpsertProject(deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		js, err := jsonResult(out)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
	})
	return append(names, "upsert_project")
}

func registerProjectExecTool(s *server.MCPServer, deps Deps, names []string) []string {
	tool := mcp.NewTool("exec_project",
		mcp.WithDescription("Run a command in a configured project workspace using existing exec safety, timeout, detach, and audit behavior."),
		mcp.WithString("project", mcp.Required(), mcp.Description("project name")),
		mcp.WithString("command", mcp.Required(), mcp.Description("the shell command to run")),
		mcp.WithString("reason", mcp.Required(), mcp.Description("why this command is being run (audited)")),
		mcp.WithString("workdir", mcp.Description("workspace (default), runs, or artifact_parent")),
		mcp.WithBoolean("unsafe", mcp.Description("bypass the dangerous-command filter")),
		mcp.WithNumber("timeout_seconds", mcp.Description("max seconds before the command is killed; 0 = no timeout; default 60")),
		mcp.WithBoolean("detach", mcp.Description("run the command in the background and return immediately")),
		mcp.WithString("platform", mcp.Description("detach platform override: auto|posix|windows"),
			mcp.Enum("auto", "posix", "windows")))
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleExecProject(ctx, deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		js, err := jsonResult(out)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
	})
	return append(names, "exec_project")
}
