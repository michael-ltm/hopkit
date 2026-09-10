package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	markmcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
)

func TestCloudToolsSchemasAndReadOnly(t *testing.T) {
	for _, writable := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "config.toml")
		session := NewCloudSession(path)
		t.Cleanup(session.Close)
		s, _ := NewServer(Deps{ConfigPath: path, AllowWrite: writable, CloudSession: session})
		for _, name := range []string{"cloud_unlock", "cloud_unlock_status", "cloud_lock"} {
			tool := s.GetTool(name)
			if !writable {
				require.Nil(t, tool)
				continue
			}
			require.NotNil(t, tool)
			require.Equal(t, false, tool.Tool.InputSchema.AdditionalProperties)
			if name == "cloud_unlock_status" {
				require.Empty(t, tool.Tool.InputSchema.Properties)
				require.Empty(t, tool.Tool.InputSchema.Required)
			} else {
				require.Len(t, tool.Tool.InputSchema.Properties, 1)
				require.ElementsMatch(t, []string{"reason"}, tool.Tool.InputSchema.Required)
			}
		}
	}
}

func TestCloudToolsRejectUnsafeInputsWithoutEcho(t *testing.T) {
	dir := t.TempDir()
	session := NewCloudSession(filepath.Join(dir, "config.toml"))
	t.Cleanup(session.Close)
	s, _ := NewServer(Deps{ConfigPath: filepath.Join(dir, "config.toml"), AuditPath: filepath.Join(dir, "audit.log"), AllowWrite: true, CloudSession: session})
	for _, name := range []string{"cloud_unlock", "cloud_lock", "cloud_unlock_status"} {
		tool := s.GetTool(name)
		require.NotNil(t, tool)
		cases := []map[string]any{{"reason": "test", "password": "unique-secret-marker"}, {"root_public": "unique-secret-marker"}, {"endpoint": "unique-secret-marker"}, {"unique-secret-marker": "test"}}
		if name != "cloud_unlock_status" {
			cases = append(cases, map[string]any{}, map[string]any{"reason": "  "}, map[string]any{"reason": 42}, map[string]any{"reason": "password=unique-secret-marker"}, map[string]any{"reason": "first\nunique-secret-marker"}, map[string]any{"reason": strings.Repeat("x", 1025)})
		}
		for _, args := range cases {
			out, err := tool.Handler(context.Background(), markmcp.CallToolRequest{Params: markmcp.CallToolParams{Name: name, Arguments: args}})
			require.NoError(t, err)
			encoded, err := json.Marshal(out)
			require.NoError(t, err)
			require.Contains(t, string(encoded), "bad_request")
			require.NotContains(t, string(encoded), "unique-secret-marker")
		}
	}
	_, err := os.Stat(filepath.Join(dir, "audit.log"))
	require.True(t, os.IsNotExist(err))
}

func TestCloudToolsStatusAndAuditNeverEchoReason(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	session := NewCloudSession(filepath.Join(dir, "config.toml"))
	t.Cleanup(session.Close)
	s, _ := NewServer(Deps{ConfigPath: filepath.Join(dir, "config.toml"), AuditPath: auditPath, AllowWrite: true, CloudSession: session})
	for _, name := range []string{"cloud_unlock_status", "cloud_lock", "cloud_unlock"} {
		tool := s.GetTool(name)
		require.NotNil(t, tool)
		args := map[string]any{}
		if name != "cloud_unlock_status" {
			args["reason"] = "unique-private-reason"
		}
		out, err := tool.Handler(context.Background(), markmcp.CallToolRequest{Params: markmcp.CallToolParams{Name: name, Arguments: args}})
		require.NoError(t, err)
		content, ok := out.Content[0].(markmcp.TextContent)
		require.True(t, ok)
		require.NotContains(t, content.Text, "unique-private-reason")
		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(content.Text), &decoded))
		for key := range decoded {
			require.Contains(t, []string{"state", "approval_url", "code", "expires_at", "message", "error"}, key)
		}
	}
	data, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "unique-private-reason")
	require.Contains(t, string(data), "cloud_lock")
	require.Contains(t, string(data), "cloud_unlock")
}

func TestReadOnlyCloudOptionsDoNotGrantCredentialAccess(t *testing.T) {
	session := NewCloudSession(filepath.Join(t.TempDir(), "config.toml"))
	defer session.Close()
	opts := (Deps{CloudSession: session, AllowWrite: false}).sshOptions(context.Background(), sshpkg.BuildOpts{})
	require.NotNil(t, opts.ResolveCloud, "read-only browser mode must never fall back to local credentials")
	_, _, cleanup, err := opts.ResolveCloud(&config.Server{Auth: config.AuthCloud, CloudEntry: "entry"}, opts)
	if cleanup != nil {
		cleanup()
	}
	require.Error(t, err)
	opts = (Deps{CloudSession: session, AllowWrite: true}).sshOptions(context.Background(), sshpkg.BuildOpts{})
	require.NotNil(t, opts.ResolveCloud)
}
