package ssh

import (
	"errors"

	"github.com/pkg/sftp"
)

// NewSFTP opens an SFTP subsystem over the existing SSH connection. The caller
// owns the returned *sftp.Client and must Close it. The underlying SSH
// connection (and any auxiliary closers) is still released by Client.Close.
func (c *Client) NewSFTP() (*sftp.Client, error) {
	if c.conn == nil {
		return nil, errors.New("ssh client not connected")
	}
	return sftp.NewClient(c.conn)
}
