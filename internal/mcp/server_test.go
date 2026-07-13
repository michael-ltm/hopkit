package mcp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewServer_RegistersExpectedTools(t *testing.T) {
	deps := Deps{ConfigPath: "/tmp/none.toml", AuditPath: "/tmp/audit.log", AllowWrite: true}
	s, names := NewServer(deps)
	require.NotNil(t, s)
	for _, want := range []string{
		"list_servers", "get_server", "test_connection", "check_ssh", "get_status", "list_projects", "get_project",
		"add_server", "edit_server", "remove_server", "upsert_project",
		"exec", "exec_multi", "exec_project",
		"bootstrap", "gen_key", "copy_id", "tail_logs",
		"upload", "download", "transfer_start", "transfer_status",
	} {
		require.Contains(t, names, want, "tool %q not registered", want)
	}
}

func TestNewServer_ReadOnlyOmitsWriteTools(t *testing.T) {
	deps := Deps{ConfigPath: "/tmp/none.toml", AuditPath: "/tmp/audit.log", AllowWrite: false}
	_, names := NewServer(deps)
	// Only read tools must be present.
	require.ElementsMatch(t, []string{"list_servers", "get_server", "test_connection", "check_ssh", "get_status", "list_projects", "get_project"}, names)
	// No write/exec/ops tools.
	for _, forbidden := range []string{"add_server", "edit_server", "remove_server", "upsert_project", "exec", "exec_multi", "exec_project", "bootstrap", "gen_key", "copy_id", "tail_logs", "upload", "download", "transfer_start", "transfer_status"} {
		require.NotContains(t, names, forbidden)
	}
}

func TestNewServerExecProjectSchema(t *testing.T) {
	s, _ := NewServer(Deps{
		ConfigPath: "/tmp/none.toml", AuditPath: "/tmp/audit.log", AllowWrite: true,
	})
	tool := s.GetTool("exec_project")
	require.NotNil(t, tool)
	require.ElementsMatch(t, []string{"project", "command", "reason"}, tool.Tool.InputSchema.Required)
	for _, field := range []string{
		"project", "command", "reason", "workdir", "unsafe", "timeout_seconds", "detach", "platform",
	} {
		require.Contains(t, tool.Tool.InputSchema.Properties, field)
	}
	platform, ok := tool.Tool.InputSchema.Properties["platform"].(map[string]any)
	require.True(t, ok)
	enum, ok := platform["enum"].([]string)
	require.True(t, ok)
	require.ElementsMatch(t, []string{"auto", "posix", "windows"}, enum)
}
