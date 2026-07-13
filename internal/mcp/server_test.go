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
		"exec", "exec_multi",
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
	for _, forbidden := range []string{"add_server", "edit_server", "remove_server", "upsert_project", "exec", "exec_multi", "bootstrap", "gen_key", "copy_id", "tail_logs", "upload", "download", "transfer_start", "transfer_status"} {
		require.NotContains(t, names, forbidden)
	}
}
