package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	"github.com/michael-ltm/sshm/internal/status"
)

// handleListServers returns every configured server with its host IP masked.
func handleListServers(deps Deps, _ map[string]any) (any, error) {
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
	return map[string]any{"servers": list}, nil
}

// handleGetServer returns one server record (host masked).
func handleGetServer(deps Deps, args map[string]any) (any, error) {
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
func handleTestConnection(deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	r := status.Probe(context.Background(), s, 5*time.Second)
	return map[string]any{
		"alias": alias, "reachable": r.Reachable,
		"latency_ms": r.Latency.Milliseconds(), "error": r.Error,
	}, nil
}

// handleGetStatus collects a rich snapshot of a server.
func handleGetStatus(deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	reg := func(name, desc string, fn func(Deps, map[string]any) (any, error)) {
		tool := mcp.NewTool(name, mcp.WithDescription(desc),
			mcp.WithString("alias", mcp.Description("server alias")))
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := fn(deps, req.GetArguments())
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
	reg("get_status", "Collect a server's uptime/load/mem/disk snapshot.", handleGetStatus)
	return names
}
