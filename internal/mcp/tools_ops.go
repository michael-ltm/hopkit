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
	"github.com/michael-ltm/sshm/internal/keystore"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

func handleBootstrap(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")

	// Plain load to read server details for the SSH call.  We do not hold the
	// config mutex during the (potentially long) network operation.
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	res, err := bootstrap.Run(ctx, s)
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	if res.Completed {
		// Use Update so the write is serialized against concurrent mutations.
		if uerr := config.Update(deps.ConfigPath, func(cfg *config.Config) error {
			if s2, ok := cfg.Servers[alias]; ok {
				s2.InitState = config.InitBootstrapped
			}
			return nil
		}); uerr != nil {
			return errResult("config", uerr.Error()), nil
		}
	}
	audit(deps, safety.Entry{Tool: "bootstrap", Alias: alias, Reason: reason,
		Result: fmt.Sprintf("completed=%v", res.Completed)})
	return map[string]any{"alias": alias, "completed": res.Completed, "sshd_state": res.SSHDState}, nil
}

func handleGenKey(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")

	// Plain load to check the alias exists before generating any files.
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	if _, ok := cfg.Servers[alias]; !ok {
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
	passphrase, err := keys.RandomPassphrase()
	if err != nil {
		return errResult("keygen", err.Error()), nil
	}
	pub, err := keys.GenerateED25519Encrypted(expanded, alias+"@sshm", passphrase)
	if err != nil {
		return errResult("keygen", err.Error()), nil
	}
	// Best-effort: the encrypted key on disk is the primary deliverable and
	// is valid regardless of agent/keychain availability (e.g. a headless
	// host with no ssh-agent), so a keystore failure must not fail gen_key
	// or orphan the key file already written to disk.
	store := keystore.BestEffort(keystore.StoreAndLoad(expanded, passphrase))

	recoveryPath, err := keys.WriteRecovery(expanded, passphrase)
	if err != nil {
		keys.RemoveGenerated(expanded)
		return errResult("recovery", fmt.Errorf("write recovery for %s: %w", expanded, err).Error()), nil
	}

	// Use Update so the KeyPath/Auth write is serialized against concurrent mutations.
	if uerr := config.Update(deps.ConfigPath, func(cfg *config.Config) error {
		if s, ok := cfg.Servers[alias]; ok {
			s.KeyPath = path
			if s.Auth != config.AuthKey {
				s.Auth = config.AuthKey
			}
		}
		return nil
	}); uerr != nil {
		keys.RemoveGenerated(expanded)
		return errResult("config", fmt.Errorf("update config after generating %s: %w", expanded, uerr).Error()), nil
	}
	audit(deps, safety.Entry{Tool: "gen_key", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{
		"alias":         alias,
		"key_path":      expanded,
		"public_key":    strings.TrimSpace(pub),
		"encrypted":     true,
		"persisted":     store.Persisted,
		"recovery_file": recoveryPath,
		"note":          store.Note,
	}, nil
}

func handleCopyID(ctx context.Context, deps Deps, args map[string]any) (any, error) {
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

// clampLines returns the number of tail lines, clamped to [1, maxTailLines],
// with a default of defaultTailLines when lines is 0.
const (
	defaultTailLines = 100
	maxTailLines     = 5000
)

func clampLines(lines int) int {
	if lines <= 0 {
		return defaultTailLines
	}
	if lines > maxTailLines {
		return maxTailLines
	}
	return lines
}

var runTailLogsRemote = executeTailLogsRemote

func handleTailLogs(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	path := strArg(args, "path")
	if path == "" {
		return errResult("bad_request", "path is required"), nil
	}
	platform := strings.ToLower(strings.TrimSpace(strArg(args, "platform")))
	switch platform {
	case "", "auto":
		platform = "auto"
	case "posix", "windows":
	default:
		return errResult("bad_request", "platform must be auto, posix, or windows"), nil
	}
	n := defaultTailLines
	if v, ok := args["lines"].(float64); ok {
		n = clampLines(int(v))
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	platform, res, errKind, err := runTailLogsRemote(ctx, deps, s, platform, path, n)
	if err != nil {
		return errResult(errKind, safety.MaskSecrets(err.Error())), nil
	}
	out := buildTailLogsResult(alias, path, platform, res)
	if _, failed := out["error"]; failed {
		audit(deps, safety.Entry{Tool: "tail_logs", Alias: alias, Reason: reason, Result: fmt.Sprintf("exit %d", res.ExitCode)})
		return out, nil
	}
	audit(deps, safety.Entry{Tool: "tail_logs", Alias: alias, Reason: reason, Result: "ok"})
	return out, nil
}

func executeTailLogsRemote(ctx context.Context, deps Deps, s *config.Server, platform, path string, lines int) (string, *sshpkg.ExecResult, string, error) {
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath})
	if err != nil {
		return platform, nil, "ssh", err
	}
	defer cli.Close()
	if platform == "auto" {
		platform = detectRemoteDetachPlatform(ctx, cli)
	}
	res, err := cli.Exec(ctx, tailCommand(platform, path, lines))
	if err != nil {
		return platform, res, "exec", err
	}
	return platform, res, "", nil
}

func tailCommand(platform, path string, lines int) string {
	if strings.EqualFold(platform, "windows") {
		script := fmt.Sprintf("Get-Content -LiteralPath %s -Tail %d", powershellSingleQuote(path), lines)
		return powershellEncodedCommand(script)
	}
	return fmt.Sprintf("tail -n %d %s", lines, shellQuoteArg(path))
}

func buildTailLogsResult(alias, path, platform string, res *sshpkg.ExecResult) map[string]any {
	if res.ExitCode != 0 {
		message := fmt.Sprintf("tail command exited %d", res.ExitCode)
		if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
			message += ": " + stderr
		}
		return errResult("exec", safety.MaskSecrets(message))
	}
	return map[string]any{
		"alias": alias, "path": path, "platform": platform,
		"lines": safety.MaskSecrets(res.Stdout),
	}
}

// shellQuoteArg single-quotes a path so it survives as one shell argument.
func shellQuoteArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// registerOpsTools registers bootstrap, gen_key, copy_id, tail_logs.
func registerOpsTools(s *server.MCPServer, deps Deps, names []string) []string {
	reg := func(name, desc string, fn func(context.Context, Deps, map[string]any) (any, error), extra ...mcp.ToolOption) {
		opts := append([]mcp.ToolOption{
			mcp.WithDescription(desc),
			mcp.WithString("alias", mcp.Description("server alias")),
			mcp.WithString("reason", mcp.Description("why (required, audited)")),
		}, extra...)
		tool := mcp.NewTool(name, opts...)
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := fn(ctx, deps, req.GetArguments())
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
	reg("tail_logs", "Tail a remote log file using the remote platform's native command.", handleTailLogs,
		mcp.WithString("path", mcp.Description("remote log file path")),
		mcp.WithString("platform", mcp.Description("remote platform override: auto|posix|windows"),
			mcp.Enum("auto", "posix", "windows")),
		mcp.WithNumber("lines", mcp.Description("number of trailing lines (default 100, max 5000)")))
	return names
}
