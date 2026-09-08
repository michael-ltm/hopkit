//go:build darwin

package desktopsession

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testConnection(t *testing.T) (*net.UnixConn, <-chan struct{}, context.CancelFunc) {
	t.Helper()
	// Darwin sockaddr_un is short; t.TempDir paths can exceed its limit.
	d, e := os.MkdirTemp("/tmp", "sshm-ipc-test-")
	require.NoError(t, e)
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(d, "s"), Net: "unix"})
	require.NoError(t, e)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.AcceptUnix()
		if e == nil {
			serveConnection(ctx, c, "test-version")
		}
	}()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(d, "s"), Net: "unix"})
	require.NoError(t, e)
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c, done, cancel
}

func TestDesktopIPCStreamsOutputAndPreservesExit(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	c, done, _ := testConnection(t)
	require.NoError(t, sameUser(c))
	require.NoError(t, json.NewEncoder(c).Encode(request{Protocol: 1, Op: "exec", Directory: t.TempDir(), Command: "printf 'ordinary output\\n'; printf 'diagnostic\\n' >&2; exit 17"}))
	dec := json.NewDecoder(c)
	var stdout, stderr strings.Builder
	for {
		var f frame
		require.NoError(t, dec.Decode(&f))
		if f.Kind == "stdout" {
			stdout.Write(f.Data)
		}
		if f.Kind == "stderr" {
			stderr.Write(f.Data)
		}
		if f.Kind == "exit" {
			require.Equal(t, 17, f.Code)
			break
		}
	}
	require.Contains(t, stdout.String(), "ordinary output\n")
	require.Contains(t, stderr.String(), "diagnostic\n")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
}

func TestDesktopIPCDisconnectCancelsChild(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	c, done, _ := testConnection(t)
	require.NoError(t, json.NewEncoder(c).Encode(request{Protocol: 1, Op: "exec", Directory: t.TempDir(), Command: "printf 'READY\\n'; exec /bin/sleep 30"}))
	dec := json.NewDecoder(c)
	for {
		var f frame
		require.NoError(t, dec.Decode(&f))
		if strings.Contains(string(f.Data), "READY") {
			break
		}
	}
	require.NoError(t, c.Close())
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnected client left child running")
	}
}

func TestDesktopIPCParentCancellation(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	c, done, cancel := testConnection(t)
	require.NoError(t, json.NewEncoder(c).Encode(request{Protocol: 1, Op: "exec", Directory: t.TempDir(), Command: "printf 'READY\\n'; exec /bin/sleep 30"}))
	dec := json.NewDecoder(c)
	for {
		var f frame
		require.NoError(t, dec.Decode(&f))
		if strings.Contains(string(f.Data), "READY") {
			break
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("service shutdown left child running")
	}
}

func TestDesktopIPCPingAndMalformedRequest(t *testing.T) {
	t.Run("ping", func(t *testing.T) {
		c, _, _ := testConnection(t)
		require.NoError(t, json.NewEncoder(c).Encode(request{Protocol: 1, Op: "ping"}))
		var f frame
		require.NoError(t, json.NewDecoder(c).Decode(&f))
		require.Equal(t, "pong", f.Kind)
		require.Equal(t, "test-version", f.Version)
	})
	t.Run("unknown protocol", func(t *testing.T) {
		c, _, _ := testConnection(t)
		require.NoError(t, json.NewEncoder(c).Encode(request{Protocol: 9, Op: "exec", Command: "touch must-not-run"}))
		var f frame
		require.Error(t, json.NewDecoder(c).Decode(&f))
	})
	t.Run("relative cwd", func(t *testing.T) {
		c, _, _ := testConnection(t)
		require.NoError(t, json.NewEncoder(c).Encode(request{Protocol: 1, Op: "exec", Directory: ".", Command: "touch must-not-run"}))
		var f frame
		require.NoError(t, json.NewDecoder(c).Decode(&f))
		require.Equal(t, 64, f.Code)
	})
}

func TestDesktopPrivatePathsRejectSymlinksAndBroadModes(t *testing.T) {
	d := t.TempDir()
	require.NoError(t, os.Chmod(d, 0700))
	require.NoError(t, ownedPrivate(d, true))
	p := filepath.Join(d, "private")
	require.NoError(t, os.WriteFile(p, []byte("1"), 0600))
	require.NoError(t, ownedPrivate(p, false))
	link := filepath.Join(d, "link")
	require.NoError(t, os.Symlink(p, link))
	require.Error(t, ownedPrivate(link, false))
	require.NoError(t, os.Chmod(p, 0644))
	require.Error(t, ownedPrivate(p, false))
}

func TestDesktopServerRefusesBackgroundSession(t *testing.T) {
	// Unit tests normally run outside Aqua in CI; when locally inside Aqua this
	// assertion is intentionally skipped instead of starting a real desktop job.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, Serve(ctx, "test"))
}
