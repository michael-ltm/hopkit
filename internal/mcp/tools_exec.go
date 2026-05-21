package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

func handleExec(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	command := strArg(args, "command")
	if command == "" {
		return errResult("bad_request", "command is required"), nil
	}
	unsafe, _ := args["unsafe"].(bool)
	if !unsafe {
		if hit, why := safety.IsDangerous(command); hit {
			audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason,
				Result: "blocked: dangerous command"})
			return errResult("dangerous",
				fmt.Sprintf("dangerous command blocked (%s); pass unsafe=true to override", why)), nil
		}
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	defer cli.Close()
	res, err := cli.Exec(ctx, command)
	if err != nil {
		return errResult("exec", safety.MaskSecrets(err.Error())), nil
	}
	audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason,
		Result: fmt.Sprintf("exit %d", res.ExitCode)})
	return map[string]any{
		"alias": alias, "exit": res.ExitCode,
		"stdout": safety.MaskSecrets(res.Stdout),
		"stderr": safety.MaskSecrets(res.Stderr),
	}, nil
}

// handleExecMulti runs the same command across several aliases sequentially.
func handleExecMulti(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	command := strArg(args, "command")
	rawAliases, _ := args["aliases"].([]any)
	if command == "" || len(rawAliases) == 0 {
		return errResult("bad_request", "aliases (array) and command are required"), nil
	}
	results := map[string]any{}
	for _, ra := range rawAliases {
		alias, _ := ra.(string)
		single, _ := handleExec(deps, map[string]any{
			"alias": alias, "command": command, "reason": reason,
			"unsafe": args["unsafe"],
		})
		results[alias] = single
	}
	return map[string]any{"results": results}, nil
}

// registerExecTools registers exec and exec_multi.
func registerExecTools(s *server.MCPServer, deps Deps, names []string) []string {
	execTool := mcp.NewTool("exec",
		mcp.WithDescription("Run a command on a server. Dangerous commands are blocked unless unsafe=true. Requires reason; audited."),
		mcp.WithString("alias", mcp.Description("server alias")),
		mcp.WithString("command", mcp.Description("the shell command to run")),
		mcp.WithString("reason", mcp.Description("why (required, audited)")),
		mcp.WithBoolean("unsafe", mcp.Description("bypass the dangerous-command filter")))
	s.AddTool(execTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleExec(deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		js, _ := jsonResult(out)
		return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
	})
	names = append(names, "exec")

	multiTool := mcp.NewTool("exec_multi",
		mcp.WithDescription("Run one command across several servers. Requires reason; audited."),
		mcp.WithArray("aliases", mcp.Description("list of server aliases")),
		mcp.WithString("command", mcp.Description("the shell command to run")),
		mcp.WithString("reason", mcp.Description("why (required, audited)")),
		mcp.WithBoolean("unsafe", mcp.Description("bypass the dangerous-command filter")))
	s.AddTool(multiTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleExecMulti(deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		js, _ := jsonResult(out)
		return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
	})
	names = append(names, "exec_multi")
	return names
}
