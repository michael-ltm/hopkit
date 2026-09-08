package mcp

import (
	"context"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"time"
)

func registerEnvironmentTool(s *server.MCPServer, deps Deps, names []string) []string {
	s.AddTool(mcp.NewTool("check_environment",
		mcp.WithDescription("Diagnose CLI discovery and verify GitHub API access without printing credentials. Checks only this session; unavailable access is NOT proof that the desktop user is logged out. Omit alias for the local MCP process. No login/logout or credential changes. Requires reason."),
		mcp.WithString("alias", mcp.Description("optional remote SSH alias; absent checks local process")),
		mcp.WithString("reason", mcp.Required(), mcp.Description("why the check is needed"))), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		reason, err := requireReason(args)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		alias := strArg(args, "alias")
		var report *sshpkg.EnvironmentReport
		if alias == "" {
			report, err = sshpkg.CheckLocalEnvironment(ctx)
		} else {
			cfg, e := config.Load(deps.ConfigPath)
			if e != nil {
				return mcp.NewToolResultError(safety.MaskSecrets(e.Error())), nil
			}
			target, ok := cfg.Servers[alias]
			if !ok {
				return mcp.NewToolResultError("unknown server alias"), nil
			}
			c, e := sshpkg.Dial(target, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath, Alias: alias, ProbeOnly: true})
			if e != nil {
				return mcp.NewToolResultError(safety.MaskSecrets(e.Error())), nil
			}
			defer c.Close()
			report, err = c.CheckEnvironment(ctx)
		}
		result := "checked"
		if err != nil {
			result = "unknown"
		}
		audit(deps, safety.Entry{Tool: "check_environment", Alias: alias, Reason: reason, Result: result})
		if err != nil {
			return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
		}
		js, e := maskedJSONResult(report)
		if e != nil {
			return mcp.NewToolResultError(e.Error()), nil
		}
		return mcp.NewToolResultText(js), nil
	})
	return append(names, "check_environment")
}
