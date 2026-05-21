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
		"list_servers", "get_server", "test_connection", "get_status",
		"add_server", "edit_server", "remove_server",
		"exec", "exec_multi",
		"bootstrap", "gen_key", "copy_id", "tail_logs",
	} {
		require.Contains(t, names, want, "tool %q not registered", want)
	}
}
