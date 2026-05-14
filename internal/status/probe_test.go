package status

import (
	"context"
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
	require.True(t, r.Latency > 0)
}
