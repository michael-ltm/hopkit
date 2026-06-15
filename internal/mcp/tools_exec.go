package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

// defaultExecTimeout is used when timeout_seconds is absent or invalid.
const defaultExecTimeout = 60 * time.Second

// detachLaunchTimeout bounds the background-launcher command (which returns
// immediately) so a wedged remote can't hang the tool.
const detachLaunchTimeout = 15 * time.Second

// execMultiConcurrency caps how many aliases exec_multi dials at once.
const execMultiConcurrency = 8

// execTimeout resolves the command timeout from args. MCP numbers arrive as
// float64. Absent or invalid-negative defaults to 60s; 0 means NO timeout
// (returned as a 0 duration so the caller runs the command unbounded).
func execTimeout(args map[string]any) time.Duration {
	v, ok := args["timeout_seconds"].(float64)
	if !ok {
		return defaultExecTimeout
	}
	if v < 0 {
		return defaultExecTimeout
	}
	return time.Duration(v) * time.Second
}

func handleExec(ctx context.Context, deps Deps, args map[string]any) (any, error) {
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
	detach, _ := args["detach"].(bool)
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
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	defer cli.Close()

	if detach {
		return runDetached(ctx, deps, cli, alias, command, reason, unsafe)
	}

	timeout := execTimeout(args)
	cmdCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	res, err := cli.Exec(cmdCtx, command)
	if err != nil {
		// Timeout / cancellation: ssh.Exec returns the partial output captured
		// so far plus ctx.Err(). Surface that partial output instead of dropping
		// it on the floor.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason,
				Result: fmt.Sprintf("timed out after %s", timeout)})
			out := map[string]any{
				"alias":  alias,
				"exit":   -1,
				"stdout": safety.MaskSecrets(res.Stdout),
				"stderr": safety.MaskSecrets(res.Stderr),
				"error": fmt.Sprintf("command timed out after %ds; raise timeout_seconds or use detach:true",
					int(timeout.Seconds())),
			}
			if errors.Is(err, context.DeadlineExceeded) {
				out["timed_out"] = true
			}
			if res.Truncated {
				out["truncated"] = true
			}
			return out, nil
		}
		// Genuine non-timeout exec error.
		return errResult("exec", safety.MaskSecrets(err.Error())), nil
	}
	result := fmt.Sprintf("exit %d", res.ExitCode)
	if unsafe {
		result += " (unsafe=true — filter bypassed)"
	}
	audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason, Result: result})
	out := map[string]any{
		"alias": alias, "exit": res.ExitCode,
		"stdout": safety.MaskSecrets(res.Stdout),
		"stderr": safety.MaskSecrets(res.Stderr),
	}
	if res.Truncated {
		out["truncated"] = true
	}
	return out, nil
}

// runDetached launches command in the background on a POSIX remote and returns
// immediately. Output is redirected to a log file the caller can poll with
// tail_logs. timeout_seconds is ignored for detached commands.
func runDetached(ctx context.Context, deps Deps, cli *sshpkg.Client, alias, command, reason string, unsafe bool) (any, error) {
	logPath := fmt.Sprintf("/tmp/sshm-detach-%d.log", time.Now().UnixNano())
	// nohup + setsid (when available) fully detaches from the SSH session so the
	// command survives the connection closing. Fall back to plain nohup if
	// setsid is missing. </dev/null detaches stdin; output goes to logPath.
	inner := shellQuoteArg(command)
	wrapper := fmt.Sprintf(
		"if command -v setsid >/dev/null 2>&1; then nohup setsid sh -c %s </dev/null >%s 2>&1 & else nohup sh -c %s </dev/null >%s 2>&1 & fi",
		inner, shellQuoteArg(logPath), inner, shellQuoteArg(logPath))

	launchCtx, cancel := context.WithTimeout(ctx, detachLaunchTimeout)
	defer cancel()
	res, err := cli.Exec(launchCtx, wrapper)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return errResult("exec", "detach launcher timed out before the command could be started"), nil
		}
		return errResult("exec", safety.MaskSecrets(err.Error())), nil
	}
	if res.ExitCode != 0 {
		return errResult("exec", safety.MaskSecrets(fmt.Sprintf(
			"detach launcher exited %d: %s", res.ExitCode, res.Stderr))), nil
	}
	result := "detached"
	if unsafe {
		result += " (unsafe=true — filter bypassed)"
	}
	audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason, Result: result})
	return map[string]any{
		"alias":    alias,
		"detached": true,
		"log_path": logPath,
		"note":     "running in background; poll with tail_logs on log_path",
	}, nil
}

// handleExecMulti runs the same command across several aliases concurrently
// (bounded) and aggregates per-alias results plus succeeded/failed summaries.
func handleExecMulti(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	command := strArg(args, "command")
	rawAliases, _ := args["aliases"].([]any)
	if command == "" || len(rawAliases) == 0 {
		return errResult("bad_request", "aliases (array) and command are required"), nil
	}

	var mu sync.Mutex
	results := map[string]any{}
	succeeded := []string{}
	failed := map[string]string{}

	var wg sync.WaitGroup
	sem := make(chan struct{}, execMultiConcurrency)

	for i, ra := range rawAliases {
		alias, ok := ra.(string)
		if !ok || strings.TrimSpace(alias) == "" {
			// Invalid entry: don't dispatch; record under a stable key.
			key := alias
			if key == "" {
				key = fmt.Sprintf("<invalid #%d>", i)
			}
			mu.Lock()
			failed[key] = "invalid alias entry (must be a non-empty string)"
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(alias string) {
			defer wg.Done()
			defer func() { <-sem }()
			single, _ := handleExec(ctx, deps, map[string]any{
				"alias": alias, "command": command, "reason": reason,
				"unsafe":          args["unsafe"],
				"timeout_seconds": args["timeout_seconds"],
			})
			ok, why := execOutcome(single)
			mu.Lock()
			results[alias] = single
			if ok {
				succeeded = append(succeeded, alias)
			} else {
				failed[alias] = why
			}
			mu.Unlock()
		}(alias)
	}
	wg.Wait()

	return map[string]any{
		"results":   results,
		"succeeded": succeeded,
		"failed":    failed,
	}, nil
}

// execOutcome inspects a single handleExec result map and reports whether it
// succeeded (exit==0) and, if not, a short reason for the failed summary.
func execOutcome(single any) (bool, string) {
	m, ok := single.(map[string]any)
	if !ok {
		return false, "unexpected result"
	}
	if e, ok := m["error"].(map[string]string); ok {
		return false, e["kind"] + ": " + e["message"]
	}
	if exit, ok := m["exit"].(int); ok {
		if exit == 0 {
			return true, ""
		}
		if to, _ := m["timed_out"].(bool); to {
			return false, "timed out"
		}
		return false, fmt.Sprintf("exit %d", exit)
	}
	return false, "no exit code"
}

// registerExecTools registers exec and exec_multi.
func registerExecTools(s *server.MCPServer, deps Deps, names []string) []string {
	execTool := mcp.NewTool("exec",
		mcp.WithDescription("Run a command on a server. Dangerous commands are blocked unless unsafe=true. "+
			"timeout_seconds bounds the run (0 = no timeout, default 60); on timeout the captured partial output is "+
			"returned with timed_out=true. detach=true runs the command in the background on a POSIX remote and returns "+
			"a log_path to poll with tail_logs (assumes a POSIX shell; ignores timeout_seconds). Requires reason; audited."),
		mcp.WithString("alias", mcp.Description("server alias")),
		mcp.WithString("command", mcp.Description("the shell command to run")),
		mcp.WithString("reason", mcp.Description("why (required, audited)")),
		mcp.WithBoolean("unsafe", mcp.Description("bypass the dangerous-command filter")),
		mcp.WithNumber("timeout_seconds", mcp.Description("max seconds before the command is killed; 0 = no timeout; default 60")),
		mcp.WithBoolean("detach", mcp.Description("run the command in the background on a POSIX remote and return immediately (poll output with tail_logs)")))
	s.AddTool(execTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleExec(ctx, deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		js, _ := jsonResult(out)
		return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
	})
	names = append(names, "exec")

	multiTool := mcp.NewTool("exec_multi",
		mcp.WithDescription("Run one command across several servers concurrently. Returns results (per-alias), "+
			"succeeded (aliases with exit 0) and failed (alias -> reason). Honors timeout_seconds per alias. "+
			"Requires reason; audited."),
		mcp.WithArray("aliases", mcp.Description("list of server aliases")),
		mcp.WithString("command", mcp.Description("the shell command to run")),
		mcp.WithString("reason", mcp.Description("why (required, audited)")),
		mcp.WithBoolean("unsafe", mcp.Description("bypass the dangerous-command filter")),
		mcp.WithNumber("timeout_seconds", mcp.Description("max seconds per command before it is killed; 0 = no timeout; default 60")))
	s.AddTool(multiTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleExecMulti(ctx, deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		js, _ := jsonResult(out)
		return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
	})
	names = append(names, "exec_multi")
	return names
}
