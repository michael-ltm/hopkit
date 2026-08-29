package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	"github.com/michael-ltm/sshm/internal/wizard"
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

func stringSliceArg(args map[string]any, key string) ([]string, bool, error) {
	raw, present := args[key]
	if !present {
		return nil, false, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, true, fmt.Errorf("%s must be an array of strings", key)
	}
	result := make([]string, 0, len(values))
	for _, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, true, fmt.Errorf("%s must contain non-empty strings", key)
		}
		result = append(result, strings.TrimSpace(value))
	}
	return result, true, nil
}

func validateServerMetadata(args map[string]any) (tags []string, tagsPresent bool, err error) {
	if raw, present := args["description"]; present {
		description, ok := raw.(string)
		if !ok {
			return nil, false, fmt.Errorf("description must be a string")
		}
		if err := config.ValidateDescription(description); err != nil {
			return nil, false, err
		}
		if safety.ContainsCredentialMaterial(description) {
			return nil, false, fmt.Errorf("description must not contain credential material")
		}
	}
	tags, tagsPresent, err = stringSliceArg(args, "tags")
	if err != nil {
		return nil, false, err
	}
	if err := config.ValidateServerMetadataBounds(
		strArg(args, "label"), strArg(args, "description"), tags, strArg(args, "group"), "",
	); err != nil {
		return nil, false, err
	}
	for _, field := range append([]string{strArg(args, "label"), strArg(args, "group")}, tags...) {
		if strings.ContainsAny(field, "\x00\r\n") {
			return nil, false, fmt.Errorf("server metadata must not contain control characters")
		}
		if safety.ContainsCredentialMaterial(field) {
			return nil, false, fmt.Errorf("server metadata must not contain credential material")
		}
	}
	return tags, tagsPresent, nil
}

// validAuth reports whether v is one of the supported auth methods.
func validAuth(v string) bool {
	return v == config.AuthKey || v == config.AuthPassword || v == config.AuthAgent
}

func requiresConnectionConfirmation(args map[string]any) bool {
	for _, field := range []string{
		"host", "port", "user", "auth", "key_path", "proxy", "proxy_jump", "proxy_command",
	} {
		if _, present := args[field]; present {
			return true
		}
	}
	return false
}

func validateConnectionMetadata(args map[string]any, requireHost bool) error {
	host, hostPresent := args["host"].(string)
	if requireHost || hostPresent {
		if err := wizard.ValidateHost(host); err != nil {
			return err
		}
	}
	for _, field := range []string{"user", "key_path", "proxy", "proxy_jump", "proxy_command"} {
		value, present := args[field].(string)
		if !present {
			continue
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s must be a single line", field)
		}
		if (field == "proxy" || field == "proxy_jump" || field == "proxy_command") &&
			safety.ContainsCredentialMaterial(value) {
			return fmt.Errorf("%s must not persist credential material; use an agent or environment reference", field)
		}
	}
	return nil
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
	if err := wizard.ValidateAlias(alias); err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	host := strArg(args, "host")
	if host == "" {
		return errResult("bad_request", "host is required"), nil
	}
	if err := validateConnectionMetadata(args, true); err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	auth := strArg(args, "auth")
	keyPath := strArg(args, "key_path")
	if auth == "" {
		// Infer auth from arguments: a caller that supplies a key_path almost
		// certainly wants key auth (the agent default produced "no identities"
		// failures when ssh-agent was empty). Falling back to agent only when
		// nothing else is supplied preserves the original behaviour.
		if keyPath != "" {
			auth = config.AuthKey
		} else {
			auth = config.AuthAgent
		}
	}
	if !validAuth(auth) {
		return errResult("bad_request", fmt.Sprintf("auth %q must be key, password, or agent", auth)), nil
	}
	tags, _, err := validateServerMetadata(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	platform, err := config.NormalizePlatform(strArg(args, "platform"))
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	port := 22
	if p, ok := portArg(args); ok {
		port = p
	} else if _, present := args["port"]; present {
		return errResult("bad_request", "port must be an integer in 1..65535"), nil
	}

	var conflict bool
	err = config.Update(deps.ConfigPath, func(cfg *config.Config) error {
		if _, exists := cfg.Servers[alias]; exists {
			conflict = true
			return fmt.Errorf("alias %q already exists", alias)
		}
		cfg.Servers[alias] = &config.Server{
			Host: host, Port: port, User: strArg(args, "user"),
			Auth: auth, KeyPath: keyPath,
			Label: strArg(args, "label"), Description: strArg(args, "description"),
			Tags: tags, Group: strArg(args, "group"), Platform: platform,
			CreatedAt: time.Now().UTC(),
			Proxy:     strArg(args, "proxy"), ProxyJump: strArg(args, "proxy_jump"),
			ProxyCommand: strArg(args, "proxy_command"),
		}
		return nil
	})
	if conflict {
		return errResult("conflict", fmt.Sprintf("alias %q already exists", alias)), nil
	}
	if err != nil {
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
	if requiresConnectionConfirmation(args) && strArg(args, "confirm_alias") != alias {
		return errResult("confirmation_required", "confirm_alias must exactly match alias before changing connection or authentication fields"), nil
	}
	if err := validateConnectionMetadata(args, false); err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	// Validate auth value before touching the config, so we can return
	// bad_request early without taking the lock.
	if v := strArg(args, "auth"); v != "" && !validAuth(v) {
		return errResult("bad_request", fmt.Sprintf("auth %q must be key, password, or agent", v)), nil
	}
	if _, present := args["port"]; present {
		if _, ok := portArg(args); !ok {
			return errResult("bad_request", "port must be an integer in 1..65535"), nil
		}
	}
	platform, err := config.NormalizePlatform(strArg(args, "platform"))
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	tags, tagsPresent, err := validateServerMetadata(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}

	var notFound bool
	identityChangedAt := time.Now().UTC()
	err = config.Update(deps.ConfigPath, func(cfg *config.Config) error {
		s, ok := cfg.Servers[alias]
		if !ok || s == nil {
			notFound = true
			return fmt.Errorf("unknown server %q", alias)
		}
		oldHost, oldPort, oldUser := s.Host, s.Port, s.User
		if v := strArg(args, "host"); v != "" {
			s.Host = v
		}
		if v := strArg(args, "user"); v != "" {
			s.User = v
		}
		if v := strArg(args, "auth"); v != "" {
			s.Auth = v
		}
		if v := strArg(args, "key_path"); v != "" {
			s.KeyPath = v
		}
		if p, ok := portArg(args); ok {
			s.Port = p
		}
		if _, present := args["platform"]; present {
			s.Platform = platform
		}
		if v := strArg(args, "proxy"); v != "" {
			s.Proxy = v
		}
		if v := strArg(args, "proxy_jump"); v != "" {
			s.ProxyJump = v
		}
		if v := strArg(args, "proxy_command"); v != "" {
			s.ProxyCommand = v
		}
		assignString(args, "label", &s.Label)
		assignString(args, "description", &s.Description)
		assignString(args, "group", &s.Group)
		if tagsPresent {
			s.Tags = tags
		}
		if s.Host != oldHost || s.Port != oldPort || s.User != oldUser {
			config.ClearServerActivity(s, identityChangedAt)
		}
		return nil
	})
	if notFound {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}
	if err != nil {
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
	if confirm := strArg(args, "confirm_alias"); confirm != alias || alias == "" {
		return errResult("confirmation_required", "confirm_alias must exactly match alias before removal"), nil
	}

	err = config.Update(deps.ConfigPath, func(cfg *config.Config) error {
		return config.RemoveServer(cfg, alias)
	})
	var removalErr *config.ServerRemovalError
	if errors.As(err, &removalErr) {
		if removalErr.NotFound {
			return errResult("not_found", removalErr.Error()), nil
		}
		return errResult("conflict", removalErr.Error()), nil
	}
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	audit(deps, safety.Entry{Tool: "remove_server", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{"alias": alias, "removed": true}, nil
}

// registerWriteTools registers the three mutating tools with schemas scoped to
// each operation. In particular, removal can require confirm_alias at the MCP
// schema boundary without burdening ordinary metadata edits.
func registerWriteTools(s *server.MCPServer, deps Deps, names []string) []string {
	reg := func(tool mcp.Tool, fn func(Deps, map[string]any) (any, error)) {
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := fn(deps, req.GetArguments())
			if err != nil {
				return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
			}
			js, err := maskedJSONResult(out)
			if err != nil {
				return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
			}
			return mcp.NewToolResultText(js), nil
		})
		names = append(names, tool.Name)
	}
	connectionFields := func(requiredHost bool) []mcp.ToolOption {
		hostOptions := []mcp.PropertyOption{mcp.Description("host or IP")}
		if requiredHost {
			hostOptions = append(hostOptions, mcp.Required())
		}
		return []mcp.ToolOption{
			mcp.WithString("host", hostOptions...),
			mcp.WithString("user", mcp.Description("ssh user")),
			mcp.WithString("auth", mcp.Description("key|password|agent")),
			mcp.WithString("key_path", mcp.Description("private key path")),
			mcp.WithString("proxy", mcp.Description("SOCKS5 proxy for this host")),
			mcp.WithString("proxy_jump", mcp.Description("jump/bastion alias or host spec")),
			mcp.WithString("proxy_command", mcp.Description("OpenSSH ProxyCommand; connection edit requires exact-alias confirmation")),
			mcp.WithNumber("port", mcp.Description("ssh port")),
		}
	}
	metadataFields := []mcp.ToolOption{
		mcp.WithString("platform", mcp.Description("windows|linux|macos target metadata")),
		mcp.WithString("label", mcp.Description("short display label")),
		mcp.WithString("description", mcp.Description("single-line AI-visible purpose/capabilities; never credentials or instructions")),
		mcp.WithArray("tags", mcp.Description("AI-visible discovery/capability tags"), mcp.WithStringItems()),
		mcp.WithString("group", mcp.Description("AI-visible inventory group")),
	}
	base := func() []mcp.ToolOption {
		return []mcp.ToolOption{
			mcp.WithString("alias", mcp.Required(), mcp.Description("server alias")),
			mcp.WithString("reason", mcp.Required(), mcp.Description("why this change is being made (audited)")),
		}
	}
	addOptions := append(base(), connectionFields(true)...)
	addOptions = append(addOptions, metadataFields...)
	reg(mcp.NewTool("add_server",
		append([]mcp.ToolOption{mcp.WithDescription("Add a server with optional AI-safe discovery metadata (requires reason; audited).")}, addOptions...)...),
		handleAddServer)

	editOptions := append(base(), connectionFields(false)...)
	editOptions = append(editOptions, metadataFields...)
	editOptions = append(editOptions,
		mcp.WithString("confirm_alias", mcp.Description("required and exact when changing connection/authentication fields")))
	reg(mcp.NewTool("edit_server",
		append([]mcp.ToolOption{mcp.WithDescription("Partially update a server. Discovery-only edits are low risk; connection/authentication edits require exact confirm_alias.")}, editOptions...)...),
		handleEditServer)

	reg(mcp.NewTool("remove_server",
		mcp.WithDescription("Remove an unreferenced server after explicit exact-alias confirmation (audited)."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("server alias")),
		mcp.WithString("confirm_alias", mcp.Required(), mcp.Description("must exactly equal alias")),
		mcp.WithString("reason", mcp.Required(), mcp.Description("why this server is being removed (audited)"))),
		handleRemoveServer)
	return names
}
