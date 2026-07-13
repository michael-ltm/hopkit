// Package mcp exposes sshm's functionality as Model Context Protocol tools
// over stdio so AI assistants can manage servers. Untrusted output and errors
// pass through safety.MaskSecrets. Validated project-profile success results
// preserve exact reusable paths and references. Write tools require a reason
// and are recorded to the audit log.
package mcp

import (
	"bytes"
	"encoding/json"

	"github.com/michael-ltm/sshm/internal/safety"
)

// jsonResult serializes v to an indented JSON string for an MCP text result.
func jsonResult(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// maskedJSONResult converts v to its JSON representation, recursively masks
// every string value and object key, and only then marshals the final MCP text.
// Masking the structured value avoids corrupting JSON quotes or delimiters when
// a secret-looking value sits next to JSON syntax (for example TOKEN=secret).
func maskedJSONResult(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return "", err
	}
	return jsonResult(maskResultStrings(normalized))
}

func maskResultStrings(v any) any {
	switch typed := v.(type) {
	case string:
		return safety.MaskSecrets(typed)
	case []any:
		masked := make([]any, len(typed))
		for i, item := range typed {
			masked[i] = maskResultStrings(item)
		}
		return masked
	case map[string]any:
		masked := make(map[string]any, len(typed))
		for key, item := range typed {
			masked[safety.MaskSecrets(key)] = maskResultStrings(item)
		}
		return masked
	default:
		return typed
	}
}

// errResult builds a structured error payload for a tool failure.
func errResult(kind, msg string) map[string]any {
	return map[string]any{"error": map[string]string{"kind": kind, "message": msg}}
}
