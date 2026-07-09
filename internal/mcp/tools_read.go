package mcp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/michael-ltm/sshm/internal/status"
)

// handleListServers returns every configured server with its host IP masked,
// sorted deterministically by alias.
func handleListServers(ctx context.Context, deps Deps, _ map[string]any) (any, error) {
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	type entry struct {
		Alias      string   `json:"alias"`
		Host       string   `json:"host"`
		User       string   `json:"user"`
		Tags       []string `json:"tags,omitempty"`
		LastStatus string   `json:"last_status,omitempty"`
	}
	var list []entry
	for alias, s := range cfg.Servers {
		list = append(list, entry{
			Alias: alias, Host: safety.MaskSecrets(s.Host), User: s.User,
			Tags: s.Tags, LastStatus: s.LastStatus,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Alias < list[j].Alias })
	return map[string]any{"servers": list}, nil
}

// handleGetServer returns one server record (host masked).
func handleGetServer(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	return map[string]any{
		"alias": alias, "host": safety.MaskSecrets(s.Host), "port": s.Port,
		"user": s.User, "auth": s.Auth, "tags": s.Tags, "group": s.Group,
		"init_state": s.InitState, "last_status": s.LastStatus,
	}, nil
}

// handleTestConnection probes a server's reachability.
func handleTestConnection(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	r := status.Probe(ctx, s, 5*time.Second)
	return map[string]any{
		"alias": alias, "reachable": r.Reachable,
		"latency_ms": r.Latency.Milliseconds(),
		"error":      safety.MaskSecrets(r.Error),
	}, nil
}

type sshCheckLevel string

const (
	sshCheckTCP       sshCheckLevel = "tcp"
	sshCheckHandshake sshCheckLevel = "handshake"
	sshCheckAuth      sshCheckLevel = "auth"
	sshCheckExec      sshCheckLevel = "exec"
)

func sshCheckMode(args map[string]any) sshCheckLevel {
	switch strings.ToLower(strings.TrimSpace(strArg(args, "mode"))) {
	case string(sshCheckTCP):
		return sshCheckTCP
	case string(sshCheckHandshake):
		return sshCheckHandshake
	case string(sshCheckAuth):
		return sshCheckAuth
	case string(sshCheckExec), "":
		return sshCheckExec
	default:
		return sshCheckExec
	}
}

func handleCheckSSH(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}

	mode := sshCheckMode(args)
	out := map[string]any{"alias": alias, "mode": string(mode)}
	tcp := status.Probe(ctx, s, 5*time.Second)
	out["tcp"] = map[string]any{
		"ok":         tcp.Reachable,
		"latency_ms": tcp.Latency.Milliseconds(),
		"error":      safety.MaskSecrets(tcp.Error),
	}
	if mode == sshCheckTCP || !tcp.Reachable {
		out["ok"] = tcp.Reachable
		return out, nil
	}

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	type dialResult struct {
		cli *sshpkg.Client
		err error
	}
	ch := make(chan dialResult, 1)
	go func() {
		cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath, Timeout: 15 * time.Second})
		ch <- dialResult{cli: cli, err: err}
	}()
	var cli *sshpkg.Client
	select {
	case <-dialCtx.Done():
		out["ssh"] = map[string]any{"ok": false, "error": dialCtx.Err().Error()}
		out["ok"] = false
		return out, nil
	case got := <-ch:
		if got.err != nil {
			out["ssh"] = map[string]any{"ok": false, "error": safety.MaskSecrets(got.err.Error())}
			out["ok"] = false
			return out, nil
		}
		cli = got.cli
	}
	defer cli.Close()
	out["ssh"] = map[string]any{"ok": true}
	if mode == sshCheckHandshake || mode == sshCheckAuth {
		out["ok"] = true
		return out, nil
	}

	execCtx, execCancel := context.WithTimeout(ctx, 10*time.Second)
	defer execCancel()
	res, err := cli.Exec(execCtx, "hostname")
	if err != nil {
		out["exec"] = map[string]any{"ok": false, "error": safety.MaskSecrets(err.Error())}
		out["ok"] = false
		return out, nil
	}
	out["exec"] = map[string]any{
		"ok":     res.ExitCode == 0,
		"exit":   res.ExitCode,
		"stdout": strings.TrimSpace(safety.MaskSecrets(res.Stdout)),
		"stderr": strings.TrimSpace(safety.MaskSecrets(res.Stderr)),
	}
	out["ok"] = res.ExitCode == 0
	return out, nil
}

// handleGetStatus collects a rich snapshot of a server.
func handleGetStatus(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	snap, err := status.Collect(ctx, s)
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	return map[string]any{"alias": alias, "status": snap}, nil
}

// registerReadTools registers the four read-only tools and appends their
// names. It bridges the MCP request type to the plain handler functions.
func registerReadTools(s *server.MCPServer, deps Deps, names []string) []string {
	reg := func(name, desc string, fn func(context.Context, Deps, map[string]any) (any, error)) {
		tool := mcp.NewTool(name, mcp.WithDescription(desc),
			mcp.WithString("alias", mcp.Description("server alias")))
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
		names = append(names, name)
	}
	reg("list_servers", "List all configured servers (host IPs masked).", handleListServers)
	reg("get_server", "Get one server's configuration.", handleGetServer)
	reg("test_connection", "TCP-probe a server's reachability.", handleTestConnection)
	checkTool := mcp.NewTool("check_ssh",
		mcp.WithDescription("Check TCP reachability, SSH authentication, and optionally a minimal remote command."),
		mcp.WithString("alias", mcp.Description("server alias")),
		mcp.WithString("mode", mcp.Description("tcp|handshake|auth|exec; default exec")))
	s.AddTool(checkTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleCheckSSH(ctx, deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		js, err := jsonResult(out)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
	})
	names = append(names, "check_ssh")
	reg("get_status", "Collect a server's uptime/load/mem/disk snapshot.", handleGetStatus)
	return names
}
