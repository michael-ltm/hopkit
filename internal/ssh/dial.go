package ssh

import (
	"errors"
	"fmt"
	"io"

	"github.com/michael-ltm/sshm/internal/config"
	gssh "golang.org/x/crypto/ssh"
)

// Client is one connected SSH session owner. NOT safe for concurrent use.
type Client struct {
	server  *config.Server
	conn    *gssh.Client
	closers []io.Closer // auxiliary resources (e.g. ssh-agent socket) to close
}

// Dial opens a fresh connection. Caller must call Close.
func Dial(s *config.Server, opts BuildOpts) (*Client, error) {
	cfg, closer, err := BuildClientConfig(s, opts)
	if err != nil {
		return nil, err
	}
	c, err := gssh.Dial("tcp", Address(s), cfg)
	if err != nil {
		if closer != nil {
			closer.Close()
		}
		return nil, fmt.Errorf("dial %s: %w", Address(s), err)
	}
	return &Client{server: s, conn: c, closers: []io.Closer{closer}}, nil
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
