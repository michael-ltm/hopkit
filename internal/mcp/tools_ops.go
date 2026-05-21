package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/bootstrap"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

func handleBootstrap(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	res, err := bootstrap.Run(ctx, s)
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	if res.Completed {
		s.InitState = config.InitBootstrapped
		_ = config.Save(deps.ConfigPath, cfg)
	}
	audit(deps, safety.Entry{Tool: "bootstrap", Alias: alias, Reason: reason,
		Result: fmt.Sprintf("completed=%v", res.Completed)})
	return map[string]any{"alias": alias, "completed": res.Completed, "sshd_state": res.SSHDState}, nil
}

func handleGenKey(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	path := strArg(args, "path")
	if path == "" {
		return errResult("bad_request", "path is required"), nil
	}
	expanded, err := sshpkg.ExpandHome(path)
	if err != nil {
		return errResult("path", err.Error()), nil
	}
	pub, err := keys.GenerateED25519(expanded, alias+"@sshm")
	if err != nil {
		return errResult("keygen", err.Error()), nil
	}
	s.KeyPath = path
	_ = config.Save(deps.ConfigPath, cfg)
	audit(deps, safety.Entry{Tool: "gen_key", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{"alias": alias, "key_path": expanded, "public_key": strings.TrimSpace(pub)}, nil
}

func handleCopyID(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	audit(deps, safety.Entry{Tool: "copy_id", Alias: alias, Reason: reason,
		Result: "deferred to CLI"})
	return map[string]any{
		"alias": alias,
		"action_required": fmt.Sprintf(
			"Run `sshm copy-id %s` in a terminal — copy-id needs a password, which is never sent through the AI.", alias),
	}, nil
}

func handleTailLogs(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	path := strArg(args, "path")
	if path == "" {
		return errResult("bad_request", "path is required"), nil
	}
	n := 100
	if v, ok := args["lines"].(float64); ok && v > 0 {
		n = int(v)
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	defer cli.Close()
	res, err := cli.Exec(ctx, fmt.Sprintf("tail -n %d %s", n, shellQuoteArg(path)))
	if err != nil {
		return errResult("exec", safety.MaskSecrets(err.Error())), nil
	}
	audit(deps, safety.Entry{Tool: "tail_logs", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{"alias": alias, "path": path, "lines": safety.MaskSecrets(res.Stdout)}, nil
}

// shellQuoteArg single-quotes a path so it survives as one shell argument.
func shellQuoteArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// registerOpsTools registers bootstrap, gen_key, copy_id, tail_logs.
func registerOpsTools(s *server.MCPServer, deps Deps, names []string) []string {
	reg := func(name, desc string, fn func(Deps, map[string]any) (any, error), extra ...mcp.ToolOption) {
		opts := append([]mcp.ToolOption{
			mcp.WithDescription(desc),
			mcp.WithString("alias", mcp.Description("server alias")),
			mcp.WithString("reason", mcp.Description("why (required, audited)")),
		}, extra...)
		tool := mcp.NewTool(name, opts...)
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := fn(deps, req.GetArguments())
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			js, _ := jsonResult(out)
			return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
		})
		names = append(names, name)
	}
	reg("bootstrap", "Run baseline hardening on a server.", handleBootstrap)
	reg("gen_key", "Generate an ed25519 keypair for a server.", handleGenKey,
		mcp.WithString("path", mcp.Description("private key path")))
	reg("copy_id", "Get instructions to install the public key (password stays on the CLI).", handleCopyID)
	reg("tail_logs", "Tail a remote log file.", handleTailLogs,
		mcp.WithString("path", mcp.Description("remote log file path")),
		mcp.WithNumber("lines", mcp.Description("number of trailing lines (default 100)")))
	return names
}
