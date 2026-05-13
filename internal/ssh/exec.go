package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	gssh "golang.org/x/crypto/ssh"
)

// ExecResult is the captured output of one command.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Exec runs cmd on the remote and returns captured output. If ctx is
// canceled before the command completes, the session is closed and ctx.Err()
// is returned.
func (c *Client) Exec(ctx context.Context, cmd string) (*ExecResult, error) {
	if c.conn == nil {
		return nil, errors.New("ssh client not connected")
	}
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = sess.Signal(gssh.SIGKILL)
		_ = sess.Close() // accelerate teardown so sess.Run unblocks
		<-done           // drain goroutine before touching buffers
		return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1}, ctx.Err()
	case err := <-done:
		exit := 0
		if err != nil {
			var ee *gssh.ExitError
			if errors.As(err, &ee) {
				exit = ee.ExitStatus()
			} else {
				return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1}, err
			}
		}
		return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exit}, nil
	}
}

// StreamExec runs cmd and writes stdout/stderr to the provided writers as
// they arrive. Useful for `sshm exec` to show real-time output.
func (c *Client) StreamExec(ctx context.Context, cmd string, stdout, stderr io.Writer) (int, error) {
	if c.conn == nil {
		return -1, errors.New("ssh client not connected")
	}
	sess, err := c.conn.NewSession()
	if err != nil {
		return -1, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	sess.Stdout = stdout
	sess.Stderr = stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(gssh.SIGKILL)
		_ = sess.Close() // accelerate teardown so sess.Run unblocks
		<-done           // drain goroutine before returning
		return -1, ctx.Err()
	case err := <-done:
		if err != nil {
			var ee *gssh.ExitError
			if errors.As(err, &ee) {
				return ee.ExitStatus(), nil
			}
			return -1, err
		}
		return 0, nil
	}
}
