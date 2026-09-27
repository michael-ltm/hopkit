package status

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
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
	require.False(t, r.ObservedAt.IsZero())
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
	require.False(t, r.ObservedAt.IsZero())
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

// TestProbeMany_CancelledContext verifies that an already-cancelled context
// causes ProbeMany to launch no probes and return promptly.
func TestProbeMany_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling

	// Build a map of many servers that would take time to probe if launched.
	// We use 20 servers pointing to refused ports; with a cancelled ctx the
	// loop should bail out immediately and return far fewer than 20 results.
	servers := map[string]*config.Server{}
	for i := 0; i < 20; i++ {
		// Port 1 is refused on localhost; no actual network traffic needed.
		servers[fmt.Sprintf("s%d", i)] = &config.Server{Host: "127.0.0.1", Port: 1}
	}

	start := time.Now()
	results := ProbeMany(ctx, servers, 500*time.Millisecond)
	elapsed := time.Since(start)

	// Must return well under the total probe timeout (20 × 500ms = 10s).
	// In practice it should be <50ms; allow 3s to be generous on slow CI.
	require.Less(t, elapsed, 3*time.Second, "ProbeMany took too long with cancelled ctx")

	require.Empty(t, results, "a pre-cancelled context must not launch any probes")
}

func TestProbeUsesSOCKSRouteWhenDirectTargetIsUnreachable(t *testing.T) {
	for _, name := range []string{"ALL_PROXY", "all_proxy", "SOCKS5_PROXY", "socks5_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(name, "")
	}
	// A real local SSH server emits its identification banner; the SOCKS
	// server routes a deliberately unresolvable nominal target to that fixture.
	fixture, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer fixture.Close()
	_, raw, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := gssh.NewSignerFromKey(raw)
	require.NoError(t, err)
	fixtureConfig := &gssh.ServerConfig{NoClientAuth: true}
	fixtureConfig.AddHostKey(hostSigner)
	go func() {
		c, e := fixture.Accept()
		if e == nil {
			defer c.Close()
			server, channels, requests, handshakeErr := gssh.NewServerConn(c, fixtureConfig)
			if handshakeErr != nil {
				return
			}
			defer server.Close()
			go gssh.DiscardRequests(requests)
			for channel := range channels {
				_ = channel.Reject(gssh.Prohibited, "fixture")
			}
		}
	}()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxy.Close()
	done := make(chan error, 1)
	go func() {
		c, e := proxy.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		greeting := make([]byte, 2)
		if _, e = io.ReadFull(c, greeting); e != nil {
			done <- e
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, e = io.ReadFull(c, methods); e != nil {
			done <- e
			return
		}
		_, _ = c.Write([]byte{5, 0})
		header := make([]byte, 4)
		if _, e = io.ReadFull(c, header); e != nil {
			done <- e
			return
		}
		if header[3] != 3 {
			done <- fmt.Errorf("expected domain target")
			return
		}
		length := make([]byte, 1)
		_, e = io.ReadFull(c, length)
		if e != nil {
			done <- e
			return
		}
		address := make([]byte, int(length[0])+2)
		_, e = io.ReadFull(c, address)
		if e != nil {
			done <- e
			return
		}
		if string(address[:len(address)-2]) != "nominal-target.invalid" {
			done <- fmt.Errorf("wrong target")
			return
		}
		upstream, e := net.Dial("tcp", fixture.Addr().String())
		if e != nil {
			done <- e
			return
		}
		defer upstream.Close()
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 22})
		done <- nil
		go io.Copy(upstream, c)
		_, _ = io.Copy(c, upstream)
	}()
	result := Probe(context.Background(), &config.Server{Host: "nominal-target.invalid", Port: 22, Proxy: "socks5://" + proxy.Addr().String()}, time.Second)
	require.True(t, result.Reachable, result.Error)
	require.Equal(t, "socks5", result.Route)
	require.NoError(t, <-done)
}

func TestProbeManyWithOptionsUsesCustomConfigForJumpAlias(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing-agent"))
	path := filepath.Join(t.TempDir(), "custom.toml")
	cfg := config.New()
	cfg.Servers["bastion"] = &config.Server{Host: "127.0.0.1", User: "jump", Auth: config.AuthKey, KeyPath: "/fixture/custom-jump-key"}
	require.NoError(t, config.Save(path, cfg))
	result := ProbeManyWithOptions(context.Background(), map[string]*config.Server{"target": {Host: "nominal-target.invalid", ProxyJump: "bastion"}}, time.Second, sshpkg.BuildOpts{ConfigPath: path})
	require.Equal(t, "proxy-jump", result["target"].Route)
	require.False(t, result["target"].Reachable)
	require.Contains(t, result["target"].Error, "/fixture/custom-jump-key")
}
