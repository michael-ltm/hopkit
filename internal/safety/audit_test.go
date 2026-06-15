package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestAuditLog_AppendMasksReasonAndResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := NewAuditLog(path)
	require.NoError(t, a.Append(Entry{
		Tool:   "exec",
		Alias:  "h",
		Reason: "set DB_PASS=hunter2",
		Result: "API_KEY=leakedsecret done",
	}))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	s := string(data)
	require.NotContains(t, s, "hunter2")       // Reason masked
	require.NotContains(t, s, "leakedsecret")  // Result masked
	require.Contains(t, s, `"time":"`)         // timestamp stamped
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

// TestAuditLog_ConcurrentAppends launches N goroutines each appending one
// entry and asserts every line is valid JSON and the count equals N (no
// interleaving/corruption). Run with -race to detect data-race violations.
func TestAuditLog_ConcurrentAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := NewAuditLog(path)
	const N = 50

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			err := a.Append(Entry{
				Tool:   "exec",
				Alias:  fmt.Sprintf("server%d", i),
				Result: "ok",
			})
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, N, "expected %d lines, got %d — possible interleaving", N, len(lines))
	for _, line := range lines {
		require.True(t, json.Valid([]byte(line)), "invalid JSON line: %s", line)
	}
}
