//go:build integration

package ssh

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

//	Run with: SSHM_TEST_HOST=127.0.0.1:2222 SSHM_TEST_KEY=/tmp/test_key \
//	          go test -tags=integration ./internal/ssh/...
func TestIntegration_DialExec(t *testing.T) {
	host := os.Getenv("SSHM_TEST_HOST")
	if host == "" {
		t.Skip("set SSHM_TEST_HOST=host:port to enable")
	}
	keyPath := os.Getenv("SSHM_TEST_KEY")
	require.NotEmpty(t, keyPath, "SSHM_TEST_KEY must be set")

	host, port := splitHostPort(host)
	srv := &config.Server{
		Host: host, Port: port, User: "tester",
		Auth: config.AuthKey, KeyPath: keyPath,
	}
	c, err := Dial(srv, BuildOpts{Timeout: 10 * time.Second})
	require.NoError(t, err)
	defer c.Close()

	res, err := c.Exec(context.Background(), "echo hello")
	require.NoError(t, err)
	require.Equal(t, 0, res.ExitCode)
	require.Contains(t, res.Stdout, "hello")
}

func splitHostPort(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 22
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return host, 22
	}
	return host, port
}
