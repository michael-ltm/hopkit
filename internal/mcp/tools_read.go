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
		Alias              string     `json:"alias"`
		Host               string     `json:"host"`
		User               string     `json:"user"`
		Description        string     `json:"description,omitempty"`
		DescriptionMissing bool       `json:"description_missing,omitempty"`
		Group              string     `json:"group,omitempty"`
		Tags               []string   `json:"tags,omitempty"`
		Platform           string     `json:"platform,omitempty"`
		LastStatus         string     `json:"last_status,omitempty"`
		LastUsed           *time.Time `json:"last_used,omitempty"`
	}
	var list []entry
	for alias, s := range cfg.Servers {
		if s == nil {
			continue
		}
		list = append(list, entry{
			Alias: alias, Host: safety.MaskSecrets(s.Host), User: s.User,
			Description: s.Description, DescriptionMissing: strings.TrimSpace(s.Description) == "", Group: s.Group,
			Tags: s.Tags, Platform: s.Platform, LastStatus: s.LastStatus, LastUsed: optionalTimestamp(s.LastUsed),
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Alias < list[j].Alias })
	return map[string]any{"servers": list, "metadata_untrusted": true}, nil
}

// handleGetServer returns one server record (host masked).
func handleGetServer(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok || s == nil {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	result := map[string]any{
		"alias": alias, "host": safety.MaskSecrets(s.Host), "port": s.Port,
		"user": s.User, "auth": s.Auth, "label": s.Label,
		"description": s.Description, "description_missing": strings.TrimSpace(s.Description) == "",
		"notes_present": strings.TrimSpace(s.Notes) != "",
		"tags":          s.Tags, "group": s.Group,
		"platform": s.Platform, "init_state": s.InitState, "last_status": s.LastStatus,
		"cleanup_protected":  s.CleanupProtected,
		"metadata_untrusted": true,
	}
	for key, value := range map[string]time.Time{
		"created_at": s.CreatedAt, "last_used": s.LastUsed,
		"identity_changed_at": s.IdentityChangedAt,
		"last_checked":        s.LastChecked, "last_seen": s.LastSeen,
	} {
		if !value.IsZero() {
			result[key] = value.UTC()
		}
	}
	return result, nil
}

// handleFindServers performs an intent lookup over aliases and descriptive
// metadata so an AI does not need to load the full inventory just to locate a
// suitable host.
func handleFindServers(_ context.Context, deps Deps, args map[string]any) (any, error) {
	query := strings.TrimSpace(strArg(args, "query"))
	if query == "" {
		return errResult("bad_request", "query is required"), nil
	}
	limit := 5
	if raw, present := args["limit"]; present {
		value, ok := raw.(float64)
		if !ok || value < 1 || value > 20 || value != float64(int(value)) {
			return errResult("bad_request", "limit must be an integer in 1..20"), nil
		}
		limit = int(value)
	}

	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	matches := config.SearchServers(cfg.Servers, query)
	if len(matches) > limit {
		matches = matches[:limit]
	}
	type entry struct {
		Alias       string     `json:"alias"`
		Description string     `json:"description,omitempty"`
		Group       string     `json:"group,omitempty"`
		Tags        []string   `json:"tags,omitempty"`
		User        string     `json:"user"`
		Host        string     `json:"host"`
		LastStatus  string     `json:"last_status,omitempty"`
		Platform    string     `json:"platform,omitempty"`
		LastUsed    *time.Time `json:"last_used,omitempty"`
		Score       int        `json:"score"`
		MatchedOn   []string   `json:"matched_on"`
	}
	list := make([]entry, 0, len(matches))
	for _, match := range matches {
		list = append(list, entry{
			Alias: match.Alias, Description: match.Server.Description,
			Group: match.Server.Group, Tags: match.Server.Tags, User: match.Server.User,
			Host: safety.MaskSecrets(match.Server.Host), LastStatus: match.Server.LastStatus,
			Platform: match.Server.Platform, LastUsed: optionalTimestamp(match.Server.LastUsed),
			Score: match.Score, MatchedOn: match.MatchedOn,
		})
	}
	return map[string]any{"query": query, "matches": list, "metadata_untrusted": true}, nil
}

func optionalTimestamp(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

// handleTestConnection probes a server's reachability.
func handleTestConnection(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	alias, _ := args["alias"].(string)
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok || s == nil {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	r := status.Probe(ctx, s, 5*time.Second)
	activityErr := config.RecordProbes(deps.ConfigPath, map[string]config.ProbeObservation{
		alias: config.NewProbeObservation(s, r.Reachable, r.ObservedAt),
	})
	out := map[string]any{
		"alias": alias, "reachable": r.Reachable,
		"latency_ms": r.Latency.Milliseconds(),
		"error":      safety.MaskSecrets(r.Error),
	}
	if warning := activityWarningText(activityErr); warning != "" {
		out["activity_warning"] = warning
	}
	return out, nil
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
	if !ok || s == nil {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}

	mode := sshCheckMode(args)
	out := map[string]any{"alias": alias, "mode": string(mode)}
	tcp := status.Probe(ctx, s, 5*time.Second)
	activityErr := config.RecordProbes(deps.ConfigPath, map[string]config.ProbeObservation{
		alias: config.NewProbeObservation(s, tcp.Reachable, tcp.ObservedAt),
	})
	out["tcp"] = map[string]any{
		"ok":         tcp.Reachable,
		"latency_ms": tcp.Latency.Milliseconds(),
		"error":      safety.MaskSecrets(tcp.Error),
	}
	if warning := activityWarningText(activityErr); warning != "" {
		out["activity_warning"] = warning
	}
	if mode == sshCheckTCP {
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
		cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath, Timeout: 15 * time.Second, Alias: alias})
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
	if !ok || s == nil {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	snap, err := status.Collect(ctx, s, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath, Alias: alias})
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
				return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
			}
			js, err := maskedJSONResult(out)
			if err != nil {
				return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
			}
			return mcp.NewToolResultText(js), nil
		})
		names = append(names, name)
	}
	reg("list_servers", "List all configured servers (host IPs masked).", handleListServers)
	findTool := mcp.NewTool("find_servers",
		mcp.WithDescription("Find the best servers for an intent using AI-safe alias, description, group, tags, user, and host metadata. Private notes are excluded."),
		mcp.WithString("query", mcp.Required(), mcp.Description("intent or capability query, e.g. 'windows dynamic-debug cdb'")),
		mcp.WithNumber("limit", mcp.Description("maximum results, 1..20; default 5")))
	s.AddTool(findTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleFindServers(ctx, deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
		}
		js, err := maskedJSONResult(out)
		if err != nil {
			return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
		}
		return mcp.NewToolResultText(js), nil
	})
	names = append(names, "find_servers")
	reg("get_server", "Get one server's configuration.", handleGetServer)
	reg("test_connection", "TCP-probe a server's reachability.", handleTestConnection)
	checkTool := mcp.NewTool("check_ssh",
		mcp.WithDescription("Check TCP reachability, SSH authentication, and optionally a minimal remote command."),
		mcp.WithString("alias", mcp.Description("server alias")),
		mcp.WithString("mode", mcp.Description("tcp|handshake|auth|exec; default exec")))
	s.AddTool(checkTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleCheckSSH(ctx, deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
		}
		js, err := maskedJSONResult(out)
		if err != nil {
			return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
		}
		return mcp.NewToolResultText(js), nil
	})
	names = append(names, "check_ssh")
	reg("get_status", "Collect a server's uptime/load/mem/disk snapshot.", handleGetStatus)
	return names
}
