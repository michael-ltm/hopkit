package ssh

import (
	"context"
	gssh "golang.org/x/crypto/ssh"
	"net"
	"time"
)

// ClientConfig.Timeout covers ssh.Dial, but not NewClientConn. Close the
// transport on expiry, including ProxyCommand pipes which ignore deadlines.
func handshake(conn net.Conn, address string, cfg *gssh.ClientConfig, timeout time.Duration) (gssh.Conn, <-chan gssh.NewChannel, <-chan *gssh.Request, error) {
	expired := make(chan struct{})
	timer := time.AfterFunc(timeout, func() { _ = conn.Close(); close(expired) })
	c, ch, req, e := gssh.NewClientConn(conn, address, cfg)
	if !timer.Stop() {
		<-expired
		if c != nil {
			_ = c.Close()
		}
		return nil, nil, nil, context.DeadlineExceeded
	}
	return c, ch, req, e
}
