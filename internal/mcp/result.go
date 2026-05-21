// Package mcp exposes sshm's functionality as Model Context Protocol tools
// over stdio so AI assistants can manage servers. Every tool response is
// passed through safety.MaskSecrets; write tools require a reason and are
// recorded to the audit log.
package mcp

import "encoding/json"

// jsonResult serializes v to an indented JSON string for an MCP text result.
func jsonResult(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// errResult builds a structured error payload for a tool failure.
func errResult(kind, msg string) map[string]any {
	return map[string]any{"error": map[string]string{"kind": kind, "message": msg}}
}
