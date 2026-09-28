package ssh

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestProbeRouteCommandValidatesEndpointAndHonorsCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix command fixture")
	}
	clearSocksEnv(t)
	for _, tc := range []struct {
		command   string
		reachable bool
	}{
		{`printf 'SSH-2.0-fixture\r\n'`, true},
		{`exit 1`, false},
		{`sleep 5`, false},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		start := time.Now()
		route, err := ProbeRoute(ctx, &config.Server{Host: "unreachable.invalid", ProxyCommand: tc.command}, BuildOpts{Timeout: time.Second})
		cancel()
		require.Equal(t, "proxy-command", route)
		if tc.reachable {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
		require.Less(t, time.Since(start), time.Second)
	}
}

func TestProbeRouteJumpUsesSSHForwardingForUnreachableNominalTarget(t *testing.T) {
	clearSocksEnv(t)
	hostSigner, _ := hostSigners(t)
	endpoint, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer endpoint.Close()
	go func() {
		conn, e := endpoint.Accept()
		if e == nil {
			defer conn.Close()
			_, _ = conn.Write([]byte("SSH-2.0-target-fixture\r\n"))
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	jump, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer jump.Close()
	forwarded := make(chan string, 1)
	go func() {
		conn, e := jump.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		cfg := &gssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(hostSigner)
		server, channels, requests, e := gssh.NewServerConn(conn, cfg)
		if e != nil {
			return
		}
		defer server.Close()
		go gssh.DiscardRequests(requests)
		for next := range channels {
			if next.ChannelType() != "direct-tcpip" {
				_ = next.Reject(gssh.UnknownChannelType, "fixture")
				continue
			}
			var request struct {
				Host       string
				Port       uint32
				OriginHost string
				OriginPort uint32
			}
			if gssh.Unmarshal(next.ExtraData(), &request) != nil {
				_ = next.Reject(gssh.Prohibited, "fixture")
				continue
			}
			upstream, e := net.Dial("tcp", endpoint.Addr().String())
			if e != nil {
				_ = next.Reject(gssh.ConnectionFailed, "fixture")
				continue
			}
			channel, channelRequests, e := next.Accept()
			if e != nil {
				_ = upstream.Close()
				continue
			}
			forwarded <- request.Host
			go gssh.DiscardRequests(channelRequests)
			go func() {
				defer channel.Close()
				defer upstream.Close()
				go io.Copy(upstream, channel)
				_, _ = io.Copy(channel, upstream)
			}()
		}
	}()
	keyPath := writeTempKey(t)
	opts := BuildOpts{Insecure: true, Timeout: time.Second, ResolveJump: func(string) (*config.Server, BuildOpts, error) {
		return &config.Server{Host: "127.0.0.1", Port: jump.Addr().(*net.TCPAddr).Port, User: "jump", Auth: config.AuthKey, KeyPath: keyPath}, BuildOpts{ConfigPath: keyPath + ".config"}, nil
	}}
	route, err := ProbeRoute(context.Background(), &config.Server{Host: "nominal-target.invalid", Port: 22, ProxyJump: "jump"}, opts)
	require.NoError(t, err)
	require.Equal(t, "proxy-jump", route)
	select {
	case host := <-forwarded:
		require.Equal(t, "nominal-target.invalid", host)
	case <-time.After(time.Second):
		t.Fatal("jump did not forward target")
	}
}
