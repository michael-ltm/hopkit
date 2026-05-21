package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditLog_AppendWritesLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := NewAuditLog(path)

	require.NoError(t, a.Append(Entry{Tool: "add_server", Alias: "prod", Reason: "new box", Result: "ok"}))
	require.NoError(t, a.Append(Entry{Tool: "exec", Alias: "prod", Reason: "deploy", Result: "exit 0"}))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "add_server")
	require.Contains(t, lines[0], "prod")
	require.Contains(t, lines[1], "exec")
}

func TestAuditLog_AppendMasksReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := NewAuditLog(path)
	require.NoError(t, a.Append(Entry{Tool: "exec", Alias: "h", Reason: "set DB_PASS=hunter2", Result: "ok"}))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "hunter2")
}

func TestAuditLog_FileIsModeSixZeroZero(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("unix only")
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	a := NewAuditLog(path)
	require.NoError(t, a.Append(Entry{Tool: "t", Alias: "h", Result: "ok"}))
	st, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}
