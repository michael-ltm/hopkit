package mcp

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/safety"
)

// cloudToolArgs deliberately rejects all fields outside this closed schema.
// Neither credentials nor account/root/endpoint overrides belong in MCP inputs.
func cloudToolArgs(args map[string]any, reasonRequired bool) bool {
	for key := range args {
		if !reasonRequired || key != "reason" {
			return false
		}
	}
	if !reasonRequired {
		return true
	}
	reason, err := requireReason(args)
	return err == nil && strings.TrimSpace(reason) != "" && len(reason) <= 1024 &&
		!strings.ContainsAny(reason, "\x00\r\n") && !safety.ContainsCredentialMaterial(reason)
}

func registerCloudTools(s *server.MCPServer, deps Deps, names []string) []string {
	for _, definition := range []struct {
		name, description string
		reason            bool
	}{
		{"cloud_unlock", "Request browser approval for cloud credential access in this MCP process. Show the user the approval URL and verification code; never request credentials in chat. Approval grants this process full vault access under existing command authority.", true},
		{"cloud_unlock_status", "Check this MCP process's browser approval and cloud credential session status.", false},
		{"cloud_lock", "Lock this MCP process's cloud credential session and cancel pending approval. Existing operations may finish.", true},
	} {
		options := []mcp.ToolOption{mcp.WithDescription(definition.description), mcp.WithSchemaAdditionalProperties(false)}
		if definition.reason {
			options = append(options, mcp.WithString("reason", mcp.Required(), mcp.Description("Brief non-secret purpose; audit records only the fixed operation category.")))
		}
		tool := mcp.NewTool(definition.name, options...)
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var out any
			if !cloudToolArgs(req.GetArguments(), definition.reason) {
				out = errResult("bad_request", "Only a non-empty, single-line, non-secret reason of at most 1024 bytes is accepted for unlock/lock; status accepts no arguments.")
			} else {
				switch definition.name {
				case "cloud_unlock":
					status, err := deps.CloudSession.Begin(ctx)
					result := "requested"
					if err != nil {
						result = "failed"
						out = errResult("cloud_unlock", err.Error())
					} else {
						out = status
					}
					audit(deps, safety.Entry{Tool: "cloud_unlock", Reason: "request browser approval", Result: result})
				case "cloud_lock":
					deps.CloudSession.Close()
					audit(deps, safety.Entry{Tool: "cloud_lock", Reason: "lock cloud session", Result: "locked"})
					out = deps.CloudSession.Status()
				default:
					out = deps.CloudSession.Status()
				}
			}
			encoded, err := maskedJSONResult(out)
			if err != nil {
				return mcp.NewToolResultError("Unable to encode cloud session status"), nil
			}
			return mcp.NewToolResultText(encoded), nil
		})
		names = append(names, definition.name)
	}
	return names
}
