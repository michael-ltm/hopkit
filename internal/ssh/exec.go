package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"

	gssh "golang.org/x/crypto/ssh"
)

// MaxCaptureBytes caps how much stdout/stderr Exec retains per stream. Output
// beyond this is dropped (and Truncated is set) to avoid blowing up the
// caller's context window or memory on a chatty command.
const MaxCaptureBytes = 256 * 1024

// cappedBuffer is an io.Writer that retains up to cap bytes and discards the
// rest, recording whether any truncation occurred.
type cappedBuffer struct {
	cap       int
	buf       []byte
	truncated bool
}

func newCappedBuffer(cap int) *cappedBuffer {
	return &cappedBuffer{cap: cap}
}

// Write always reports len(p) consumed (so the SSH session keeps draining)
// but only stores bytes up to the cap.
func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.cap - len(b.buf); room > 0 {
		if len(p) > room {
			b.buf = append(b.buf, p[:room]...)
			b.truncated = true
		} else {
			b.buf = append(b.buf, p...)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string  { return string(b.buf) }
func (b *cappedBuffer) Truncated() bool { return b.truncated }

// ExecResult is the captured output of one command.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	// Truncated is true when stdout or stderr exceeded MaxCaptureBytes and the
	// excess was dropped.
	Truncated bool
}

// Exec runs cmd on the remote and returns captured output. If ctx is
// canceled before the command completes, the session is closed and ctx.Err()
// is returned. Captured stdout/stderr are each capped at MaxCaptureBytes; if
// either stream overflows, ExecResult.Truncated is set.
func (c *Client) Exec(ctx context.Context, cmd string) (*ExecResult, error) {
	if c.conn == nil {
		return nil, errors.New("ssh client not connected")
	}
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	stdout := newCappedBuffer(MaxCaptureBytes)
	stderr := newCappedBuffer(MaxCaptureBytes)
	sess.Stdout = stdout
	sess.Stderr = stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = sess.Signal(gssh.SIGKILL)
		_ = sess.Close() // accelerate teardown so sess.Run unblocks
		<-done           // drain goroutine before touching buffers
		return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1,
			Truncated: stdout.Truncated() || stderr.Truncated()}, ctx.Err()
	case err := <-done:
		exit := 0
		if err != nil {
			var ee *gssh.ExitError
			if errors.As(err, &ee) {
				exit = ee.ExitStatus()
			} else {
				return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1,
					Truncated: stdout.Truncated() || stderr.Truncated()}, err
			}
		}
		return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exit,
			Truncated: stdout.Truncated() || stderr.Truncated()}, nil
	}
}

// StreamExec runs cmd and writes stdout/stderr to the provided writers as
// they arrive. Useful for `sshm exec` to show real-time output. This path is
// intentionally unbounded so the CLI can stream large output.
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
