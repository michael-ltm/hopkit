package commands

import (
	"bytes"
	"net"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestTest_SingleUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().(*net.TCPAddr)
	host, port := addr.IP.String(), addr.Port
	l.Close() // port now refused

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["dead"] = &config.Server{Host: host, Port: port, User: "x", Auth: config.AuthKey, KeyPath: "/k"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	flagJSON = true
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false })

	cmd := newTestCmd()
	cmd.SetArgs([]string{"dead", "--timeout", "1"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "\"reachable\": false")
}
