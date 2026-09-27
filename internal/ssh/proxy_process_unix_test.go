//go:build !windows

package ssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

// Killing only the sh process makes this child survive the route timeout.
func TestProbeRouteCancellationTerminatesProxyCommandDescendant(t *testing.T) {
	clearSocksEnv(t)
	pidfile := filepath.Join(t.TempDir(), "child.pid")
	command := fmt.Sprintf("sleep 60 & echo $! > '%s'; wait", pidfile)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	route, err := ProbeRoute(ctx, &config.Server{Host: "synthetic.invalid", ProxyCommand: command}, BuildOpts{Timeout: time.Second})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, "proxy-command", route)
	require.Less(t, time.Since(started), time.Second)
	data, err := os.ReadFile(pidfile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)
	child, err := os.FindProcess(pid)
	require.NoError(t, err)
	// Always clean up the actual spawned process, including the RED run.
	t.Cleanup(func() { _ = child.Kill() })
	require.Eventually(t, func() bool { return child.Signal(syscall.Signal(0)) != nil }, 2*time.Second, 10*time.Millisecond, "ProxyCommand child outlived cancellation")
}
