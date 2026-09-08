package ssh

import (
	"context"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"net"
	"testing"
	"time"
)

func TestHandshakeTimeoutAfterTCPAcceptedWithoutSSHBanner(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			if _, e := server.Read(b); e != nil {
				return
			}
		}
	}()
	started := time.Now()
	_, _, _, e := handshake(client, "fixture.invalid:22", &gssh.ClientConfig{User: "test", HostKeyCallback: gssh.InsecureIgnoreHostKey()}, 50*time.Millisecond)
	require.ErrorIs(t, e, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
	<-done
}
func TestSOCKSNegotiationTimeoutAfterProxyAccepted(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1024)
		for {
			if _, e = c.Read(b); e != nil {
				return
			}
		}
	}()
	started := time.Now()
	_, e = dialSOCKS5(&config.Server{Host: "fixture.invalid", Port: 22}, listener.Addr().String(), nil, 50*time.Millisecond)
	require.Error(t, e)
	require.Less(t, time.Since(started), time.Second)
	<-done
}
