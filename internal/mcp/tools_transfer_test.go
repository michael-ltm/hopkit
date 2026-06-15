package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

// transferDeps writes a config containing a dummy alias and returns Deps. The
// alias is never actually dialed in these tests because every assertion
// targets a failure that happens before Dial.
func transferDeps(t *testing.T) (Deps, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthKey}
	require.NoError(t, config.Save(cfgPath, cfg))
	return Deps{ConfigPath: cfgPath, AuditPath: filepath.Join(dir, "a.log"), AllowWrite: true}, dir
}

func errKind(t *testing.T, out any) string {
	t.Helper()
	m, ok := out.(map[string]any)
	require.True(t, ok, "result is not a map: %#v", out)
	e, ok := m["error"].(map[string]string)
	require.True(t, ok, "result has no error: %#v", out)
	return e["kind"]
}

func TestHandleUpload_MissingArgs(t *testing.T) {
	deps, dir := transferDeps(t)
	// A real local file so the missing-arg checks (which precede the file open)
	// are exercised in isolation.
	local := filepath.Join(dir, "src.txt")
	require.NoError(t, os.WriteFile(local, []byte("hi"), 0o600))

	cases := []struct {
		name string
		args map[string]any
	}{
		{"missing reason", map[string]any{"alias": "h", "local_path": local, "remote_path": "/tmp/x"}},
		{"missing alias", map[string]any{"local_path": local, "remote_path": "/tmp/x", "reason": "r"}},
		{"missing local_path", map[string]any{"alias": "h", "remote_path": "/tmp/x", "reason": "r"}},
		{"missing remote_path", map[string]any{"alias": "h", "local_path": local, "reason": "r"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := handleUpload(deps, tc.args)
			require.NoError(t, err)
			require.Equal(t, "bad_request", errKind(t, out))
		})
	}
}

func TestHandleUpload_NonexistentLocalFile(t *testing.T) {
	deps, dir := transferDeps(t)
	out, err := handleUpload(deps, map[string]any{
		"alias": "h", "local_path": filepath.Join(dir, "nope.txt"),
		"remote_path": "/tmp/x", "reason": "r",
	})
	require.NoError(t, err)
	require.Equal(t, "bad_request", errKind(t, out))
}

func TestHandleDownload_MissingArgs(t *testing.T) {
	deps, dir := transferDeps(t)
	local := filepath.Join(dir, "dst.txt")
	cases := []struct {
		name string
		args map[string]any
	}{
		{"missing reason", map[string]any{"alias": "h", "remote_path": "/tmp/x", "local_path": local}},
		{"missing alias", map[string]any{"remote_path": "/tmp/x", "local_path": local, "reason": "r"}},
		{"missing remote_path", map[string]any{"alias": "h", "local_path": local, "reason": "r"}},
		{"missing local_path", map[string]any{"alias": "h", "remote_path": "/tmp/x", "reason": "r"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := handleDownload(deps, tc.args)
			require.NoError(t, err)
			require.Equal(t, "bad_request", errKind(t, out))
		})
	}
}

func TestExpandLocalHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	got, err := expandLocalHome("~/foo/bar")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, "foo/bar"), got)

	// No leading ~ is returned unchanged.
	got, err = expandLocalHome("/abs/path")
	require.NoError(t, err)
	require.Equal(t, "/abs/path", got)

	got, err = expandLocalHome("relative/path")
	require.NoError(t, err)
	require.Equal(t, "relative/path", got)
}
