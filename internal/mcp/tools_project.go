package mcp

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
)

var projectNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

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
		return errResult("not_found", fmt.Sprintf("unknown project %q", name)), nil
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
