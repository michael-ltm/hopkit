package mcp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["prod"] = &config.Server{
		Host: "203.0.113.9", Port: 22, User: "ubuntu",
		Auth: config.AuthKey, KeyPath: "/k", Tags: []string{"prod"},
	}
	require.NoError(t, config.Save(p, cfg))
	return p
}

func TestHandleListServers_MasksHostIP(t *testing.T) {
	deps := Deps{ConfigPath: writeTestConfig(t)}
	out, err := handleListServers(context.Background(), deps, nil)
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "prod")
	require.Contains(t, js, "203.0.*.*")
	require.NotContains(t, js, "203.0.113.9")
}

func TestHandleListServers_SortedByAlias(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["b-server"] = &config.Server{Host: "1.2.3.4", User: "u", Auth: config.AuthKey}
	cfg.Servers["a-server"] = &config.Server{Host: "1.2.3.5", User: "u", Auth: config.AuthKey}
	cfg.Servers["c-server"] = &config.Server{Host: "1.2.3.6", User: "u", Auth: config.AuthKey}
	require.NoError(t, config.Save(p, cfg))

	deps := Deps{ConfigPath: p}
	out, err := handleListServers(context.Background(), deps, nil)
	require.NoError(t, err)

	// Extract the servers slice to check ordering.
	m, ok := out.(map[string]any)
	require.True(t, ok)
	list, ok := m["servers"].([]struct {
		Alias      string
		Host       string
		User       string
		Tags       []string
		LastStatus string
	})
	// The list is a slice of anonymous struct; marshal/unmarshal via JSON to inspect order.
	js, err2 := jsonResult(out)
	require.NoError(t, err2)
	_ = list
	// Verify JSON ordering: a-server < b-server < c-server.
	aIdx := indexOf(js, "a-server")
	bIdx := indexOf(js, "b-server")
	cIdx := indexOf(js, "c-server")
	require.Less(t, aIdx, bIdx, "a-server should appear before b-server")
	require.Less(t, bIdx, cIdx, "b-server should appear before c-server")
}

// indexOf returns the byte position of substr in s, or panics.
func indexOf(s, substr string) int {
	for i := range s {
		if len(s)-i >= len(substr) && s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestHandleGetServer_UnknownAliasReturnsError(t *testing.T) {
	deps := Deps{ConfigPath: writeTestConfig(t)}
	out, err := handleGetServer(context.Background(), deps, map[string]any{"alias": "nope"})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
	require.Contains(t, js, "unknown")
}
