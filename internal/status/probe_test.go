package status

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestProbe_UnreachableHostReturnsOffline(t *testing.T) {
	// Bind a listener to grab a free port, then close it immediately.
	// Connecting to a closed local port gives "connection refused" — reliably
	// unroutable regardless of network environment (avoids RFC 5737 routing
	// surprises on some hosts where 198.51.100.x is actually reachable).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // port is now closed; next connect will be refused

	srv := &config.Server{Host: "127.0.0.1", Port: port, User: "x", Auth: config.AuthKey, KeyPath: "/nope"}
	r := Probe(context.Background(), srv, 500*time.Millisecond)
	require.False(t, r.Reachable)
	require.NotEmpty(t, r.Error)
}

func TestProbe_TCPOnlyMode_ReachableLocalListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	host, port := l.Addr().(*net.TCPAddr).IP.String(), l.Addr().(*net.TCPAddr).Port

	srv := &config.Server{Host: host, Port: port}
	r := Probe(context.Background(), srv, 500*time.Millisecond)
	require.True(t, r.Reachable)
	require.Empty(t, r.Error)
	// Latency must be non-negative. It is NOT asserted strictly positive:
	// a localhost connect can complete faster than the platform clock's
	// granularity (notably on Windows), legitimately measuring as 0.
	require.GreaterOrEqual(t, r.Latency, time.Duration(0))
}

func TestProbeMany_AllReachable(t *testing.T) {
	servers := map[string]*config.Server{}
	var listeners []net.Listener
	for i := 0; i < 3; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		listeners = append(listeners, l)
		addr := l.Addr().(*net.TCPAddr)
		servers[fmt.Sprintf("srv%d", i)] = &config.Server{Host: addr.IP.String(), Port: addr.Port}
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	results := ProbeMany(context.Background(), servers, 500*time.Millisecond)
	require.Len(t, results, 3)
	for alias, r := range results {
		require.True(t, r.Reachable, "%s should be reachable", alias)
	}
}

func TestProbeMany_EmptyMapReturnsEmpty(t *testing.T) {
	results := ProbeMany(context.Background(), map[string]*config.Server{}, 500*time.Millisecond)
	require.Empty(t, results)
}

func TestProbeMany_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling

	servers := map[string]*config.Server{
		"a": {Host: "127.0.0.1", Port: 1}, // port 1 — refused/unreachable
	}
	results := ProbeMany(ctx, servers, 500*time.Millisecond)
	require.Len(t, results, 1)
	require.False(t, results["a"].Reachable)
}
