package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
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

var (
	dialExecRemote       = sshpkg.Dial
	runExecRemoteCommand = func(ctx context.Context, cli *sshpkg.Client, command string) (*sshpkg.ExecResult, error) {
		return cli.Exec(ctx, command)
	}
)

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
	cli, err := dialExecRemote(s, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath})
	if err != nil {
		audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason, Result: "ssh failed"})
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	defer cli.Close()

	if detach {
		return runDetached(ctx, deps, cli, alias, command, reason, unsafe, strArg(args, "platform"))
	}

	timeout := execTimeout(args)
	cmdCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	res, err := runExecRemoteCommand(cmdCtx, cli, command)
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
		audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason, Result: "exec failed"})
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

// runDetached launches command in the background and returns immediately.
// Output is redirected to a log file the caller can poll with tail_logs.
// timeout_seconds is ignored for detached commands.
func runDetached(ctx context.Context, deps Deps, cli *sshpkg.Client, alias, command, reason string, unsafe bool, platform string) (any, error) {
	if strings.TrimSpace(platform) == "" || strings.EqualFold(platform, "auto") {
		platform = detectRemoteDetachPlatform(ctx, cli)
	}
	launcher := buildDetachLauncher(platform, command, time.Now().UnixNano())

	launchCtx, cancel := context.WithTimeout(ctx, detachLaunchTimeout)
	defer cancel()
	res, err := runExecRemoteCommand(launchCtx, cli, launcher.Command)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason, Result: "detach launcher timed out"})
			return errResult("exec", "detach launcher timed out before the command could be started"), nil
		}
		audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason, Result: "detach launcher failed"})
		return errResult("exec", safety.MaskSecrets(err.Error())), nil
	}
	if res.ExitCode != 0 {
		audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason,
			Result: fmt.Sprintf("detach launcher exit %d", res.ExitCode)})
		return errResult("exec", safety.MaskSecrets(fmt.Sprintf(
			"detach launcher exited %d: %s", res.ExitCode, res.Stderr))), nil
	}
	return finishDetachedLaunch(deps, alias, reason, unsafe, launcher, res.Stdout), nil
}

type detachLauncher struct {
	Platform string
	Command  string
	LogPath  string
}

func parseDetachMetadata(stdout string) (pid int, logPath string) {
	for _, rawLine := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(rawLine)
		switch {
		case strings.HasPrefix(line, "pid="):
			parsed, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pid=")))
			if err == nil {
				pid = parsed
			}
		case strings.HasPrefix(line, "log="):
			logPath = strings.TrimSpace(strings.TrimPrefix(line, "log="))
		}
	}
	return pid, logPath
}

func buildDetachedResult(alias string, launcher detachLauncher, stdout string) map[string]any {
	logPath := launcher.LogPath
	pid := 0
	if launcher.Platform == "windows" {
		pid, logPath = parseDetachMetadata(stdout)
		if logPath == "" {
			out := errResult("exec", "Windows detach launcher did not return readable log metadata")
			out["alias"] = alias
			out["detached"] = true
			out["platform"] = launcher.Platform
			out["stdout"] = safety.MaskSecrets(stdout)
			if pid > 0 {
				out["pid"] = pid
			}
			return out
		}
	}
	out := map[string]any{
		"alias":    alias,
		"detached": true,
		"platform": launcher.Platform,
		"log_path": logPath,
		"stdout":   safety.MaskSecrets(stdout),
		"note":     "running in background; poll with tail_logs on log_path",
	}
	if pid > 0 {
		out["pid"] = pid
	}
	return out
}

func finishDetachedLaunch(deps Deps, alias, reason string, unsafe bool, launcher detachLauncher, stdout string) map[string]any {
	out := buildDetachedResult(alias, launcher, stdout)
	result := "detached"
	if _, failed := out["error"]; failed {
		result = "detached (log metadata unavailable)"
	}
	if unsafe {
		result += " (unsafe=true — filter bypassed)"
	}
	audit(deps, safety.Entry{Tool: "exec", Alias: alias, Reason: reason, Result: result})
	return out
}

func detectRemoteDetachPlatform(ctx context.Context, cli *sshpkg.Client) string {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := runExecRemoteCommand(probeCtx, cli, "cmd /c ver")
	if err != nil {
		return "posix"
	}
	return detectDetachPlatform(res.Stdout, res.Stderr)
}

func detectDetachPlatform(stdout, stderr string) string {
	raw := strings.ToLower(stdout + "\n" + stderr)
	if strings.Contains(raw, "microsoft windows") || strings.Contains(raw, "windows [version") {
		return "windows"
	}
	return "posix"
}

func buildDetachLauncher(platform, command string, nonce int64) detachLauncher {
	if strings.EqualFold(platform, "windows") {
		logName := fmt.Sprintf("sshm-detach-%d.log", nonce)
		scriptName := fmt.Sprintf("sshm-detach-%d.ps1", nonce)
		logPath := `$env:TEMP\` + logName
		logExpr := "(Join-Path $env:TEMP " + powershellSingleQuote(logName) + ")"
		scriptExpr := "(Join-Path $env:TEMP " + powershellSingleQuote(scriptName) + ")"
		body := strings.ReplaceAll(command, "\r\n", "\n") + " *> " + logExpr
		encodedBody := base64.StdEncoding.EncodeToString([]byte(body))
		wrapper := fmt.Sprintf(
			"$script=%s; $log=%s; $body=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(%s)); Set-Content -LiteralPath $script -Encoding UTF8 -Value $body; $p=Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script) -WindowStyle Hidden -PassThru; Write-Output ('pid=' + $p.Id); Write-Output ('log=' + $log)",
			scriptExpr, logExpr, powershellSingleQuote(encodedBody))
		return detachLauncher{Platform: "windows", Command: powershellEncodedCommand(wrapper), LogPath: logPath}
	}

	logPath := fmt.Sprintf("/tmp/sshm-detach-%d.log", nonce)
	inner := shellQuoteArg(command)
	wrapper := fmt.Sprintf(
		"if command -v setsid >/dev/null 2>&1; then nohup setsid sh -c %s </dev/null >%s 2>&1 & else nohup sh -c %s </dev/null >%s 2>&1 & fi",
		inner, shellQuoteArg(logPath), inner, shellQuoteArg(logPath))
	return detachLauncher{Platform: "posix", Command: wrapper, LogPath: logPath}
}

func powershellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
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
			"returned with timed_out=true. detach=true runs the command in the background and returns a platform-specific "+
			"log_path to poll with tail_logs (ignores timeout_seconds). Requires reason; audited."),
		mcp.WithString("alias", mcp.Description("server alias")),
		mcp.WithString("command", mcp.Description("the shell command to run")),
		mcp.WithString("reason", mcp.Description("why (required, audited)")),
		mcp.WithBoolean("unsafe", mcp.Description("bypass the dangerous-command filter")),
		mcp.WithNumber("timeout_seconds", mcp.Description("max seconds before the command is killed; 0 = no timeout; default 60")),
		mcp.WithString("platform", mcp.Description("detach platform override: auto|posix|windows")),
		mcp.WithBoolean("detach", mcp.Description("run the command in the background and return immediately (poll output with tail_logs)")))
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
