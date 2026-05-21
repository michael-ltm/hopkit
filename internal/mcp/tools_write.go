package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
)

// requireReason extracts a non-empty "reason" arg. Write tools demand it so
// every mutation is explainable in the audit log.
func requireReason(args map[string]any) (string, error) {
	r, _ := args["reason"].(string)
	if r == "" {
		return "", fmt.Errorf("a non-empty \"reason\" argument is required for write operations")
	}
	return r, nil
}

// strArg fetches a string argument, empty string if absent.
func strArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

// validAuth reports whether v is one of the supported auth methods.
func validAuth(v string) bool {
	return v == config.AuthKey || v == config.AuthPassword || v == config.AuthAgent
}

// portArg extracts a port from JSON args. JSON numbers decode as float64.
// Returns (port, ok). ok is false when absent; an out-of-range value
// returns (0, false) so the caller can reject it.
func portArg(args map[string]any) (int, bool) {
	p, ok := args["port"].(float64)
	if !ok {
		return 0, false
	}
	n := int(p)
	if n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// audit appends one record, swallowing log-write errors (the operation
// already succeeded; a failed audit write must not fail the tool).
func audit(deps Deps, e safety.Entry) {
	_ = safety.NewAuditLog(deps.AuditPath).Append(e)
}

func handleAddServer(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	if alias == "" {
		return errResult("bad_request", "alias is required"), nil
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	if _, exists := cfg.Servers[alias]; exists {
		return errResult("conflict", fmt.Sprintf("alias %q already exists", alias)), nil
	}
	host := strArg(args, "host")
	if host == "" {
		return errResult("bad_request", "host is required"), nil
	}
	auth := strArg(args, "auth")
	if auth == "" {
		auth = config.AuthAgent
	}
	if !validAuth(auth) {
		return errResult("bad_request", fmt.Sprintf("auth %q must be key, password, or agent", auth)), nil
	}
	port := 22
	if p, ok := portArg(args); ok {
		port = p
	} else if _, present := args["port"]; present {
		return errResult("bad_request", "port must be an integer in 1..65535"), nil
	}
	cfg.Servers[alias] = &config.Server{
		Host: host, Port: port, User: strArg(args, "user"),
		Auth: auth, KeyPath: strArg(args, "key_path"),
	}
	if err := config.Save(deps.ConfigPath, cfg); err != nil {
		return errResult("config", err.Error()), nil
	}
	audit(deps, safety.Entry{Tool: "add_server", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{"alias": alias, "added": true}, nil
}

func handleEditServer(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	if alias == "" {
		return errResult("bad_request", "alias is required"), nil
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	if v := strArg(args, "host"); v != "" {
		s.Host = v
	}
	if v := strArg(args, "user"); v != "" {
		s.User = v
	}
	if v := strArg(args, "auth"); v != "" {
		if !validAuth(v) {
			return errResult("bad_request", fmt.Sprintf("auth %q must be key, password, or agent", v)), nil
		}
		s.Auth = v
	}
	if v := strArg(args, "key_path"); v != "" {
		s.KeyPath = v
	}
	if p, ok := portArg(args); ok {
		s.Port = p
	} else if _, present := args["port"]; present {
		return errResult("bad_request", "port must be an integer in 1..65535"), nil
	}
	if err := config.Save(deps.ConfigPath, cfg); err != nil {
		return errResult("config", err.Error()), nil
	}
	audit(deps, safety.Entry{Tool: "edit_server", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{"alias": alias, "updated": true}, nil
}

func handleRemoveServer(deps Deps, args map[string]any) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	if _, ok := cfg.Servers[alias]; !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	delete(cfg.Servers, alias)
	if cfg.Default == alias {
		cfg.Default = ""
	}
	if err := config.Save(deps.ConfigPath, cfg); err != nil {
		return errResult("config", err.Error()), nil
	}
	audit(deps, safety.Entry{Tool: "remove_server", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{"alias": alias, "removed": true}, nil
}

// registerWriteTools registers the three mutating tools.
func registerWriteTools(s *server.MCPServer, deps Deps, names []string) []string {
	reg := func(name, desc string, fn func(Deps, map[string]any) (any, error)) {
		tool := mcp.NewTool(name, mcp.WithDescription(desc),
			mcp.WithString("alias", mcp.Description("server alias")),
			mcp.WithString("reason", mcp.Description("why this change is being made (required, audited)")),
			mcp.WithString("host", mcp.Description("host or IP")),
			mcp.WithString("user", mcp.Description("ssh user")),
			mcp.WithString("auth", mcp.Description("key|password|agent")),
			mcp.WithString("key_path", mcp.Description("private key path")),
			mcp.WithNumber("port", mcp.Description("ssh port")))
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
	reg("add_server", "Add a new server (requires reason; audited).", handleAddServer)
	reg("edit_server", "Update host/user/port/auth/key_path on a server (requires reason; audited).", handleEditServer)
	reg("remove_server", "Remove a server (requires reason; audited).", handleRemoveServer)
	return names
}
