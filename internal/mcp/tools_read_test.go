package mcp

import (
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
	out, err := handleListServers(deps, nil)
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "prod")
	require.Contains(t, js, "203.0.*.*")
	require.NotContains(t, js, "203.0.113.9")
}

func TestHandleGetServer_UnknownAliasReturnsError(t *testing.T) {
	deps := Deps{ConfigPath: writeTestConfig(t)}
	out, err := handleGetServer(deps, map[string]any{"alias": "nope"})
	require.NoError(t, err)
	js, _ := jsonResult(out)
	require.Contains(t, js, "error")
	require.Contains(t, js, "unknown")
}
