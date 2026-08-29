package ssh

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	gssh "golang.org/x/crypto/ssh"
)

// Client is one connected SSH session owner. NOT safe for concurrent use.
type Client struct {
	server  *config.Server
	conn    *gssh.Client
	closers []io.Closer // auxiliary resources (e.g. ssh-agent socket) to close
}

// Dial opens a fresh connection. Caller must call Close.
//
// The target is reached over the transport chosen by resolveTransportKind:
// ProxyCommand > ProxyJump > SOCKS5 (s.Proxy or env) > Direct. When a proxy or
// jump was selected but the connection fails, Dial retries once with a direct
// TCP dial — this recovers the common TUN/VPN case where the host is reachable
// directly but the configured SOCKS proxy is not (or vice versa is already the
// direct path).
func Dial(s *config.Server, opts BuildOpts) (*Client, error) {
	cfg, closer, err := BuildClientConfig(s, opts)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	// dialOnce performs a single connection attempt over the selected (or
	// forced-direct) transport, completing the SSH handshake. On any failure
	// it releases the transport conn and aux closers but never the agent
	// closer (owned by the caller / reused across attempts).
	dialOnce := func(forceDirect bool) (*gssh.Client, []io.Closer, transportKind, error) {
		conn, aux, kind, err := dialTransportKind(s, opts, timeout, forceDirect)
		if err != nil {
			return nil, nil, kind, err
		}
		sshConn, chans, reqs, err := gssh.NewClientConn(conn, Address(s), cfg)
		if err != nil {
			// Surface ProxyCommand stderr (masked) before tearing down the
			// process, since Close discards it.
			detail := ""
			if cc, ok := conn.(*cmdConn); ok {
				if se := cc.stderrText(); se != "" {
					detail = ": " + safety.MaskSecrets(se)
				}
			}
			conn.Close()
			if aux != nil {
				aux.Close()
			}
			return nil, nil, kind, fmt.Errorf("dial %s: %w%s", Address(s), err, detail)
		}
		client := gssh.NewClient(sshConn, chans, reqs)
		var auxClosers []io.Closer
		if aux != nil {
			auxClosers = append(auxClosers, aux)
		}
		return client, auxClosers, kind, nil
	}

	client, auxClosers, kind, err := dialOnce(false)
	if err != nil && kind != kindDirect {
		// A proxy/jump was selected and failed; fall back to a direct dial.
		directClient, directAux, directKind, directErr := dialOnce(true)
		if directErr == nil {
			client, auxClosers, kind, err = directClient, directAux, directKind, nil
		} else {
			err = fmt.Errorf("connect %s failed via %s (%v) and direct fallback (%w)",
				Address(s), kind, err, directErr)
		}
	}
	if err != nil {
		closer.Close() // nopCloser unless an ssh-agent socket was opened
		return nil, err
	}

	closers := append([]io.Closer{closer}, auxClosers...)
	activityPath := opts.ConfigPath
	if activityPath == "" {
		activityPath = config.ConfigPath()
	}
	if opts.Alias != "" {
		if err := config.RecordSSHUse(activityPath, opts.Alias, s, time.Now()); err != nil {
			reportActivityError(opts, err)
		}
	}
	return &Client{server: s, conn: client, closers: closers}, nil
}

// Close terminates the underlying TCP connection AND all auxiliary closers.
func (c *Client) Close() error {
	var firstErr error
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			firstErr = err
		}
		c.conn = nil
	}
	for _, cl := range c.closers {
		if cl == nil {
			continue
		}
		if err := cl.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	c.closers = nil
	return firstErr
}

// Underlying returns the wrapped ssh.Client. Use sparingly; tests of this
// package shouldn't need it.
func (c *Client) Underlying() (*gssh.Client, error) {
	if c.conn == nil {
		return nil, errors.New("ssh client not connected")
	}
	return c.conn, nil
}
