package ssh

import (
	"context"
	"errors"
	"io"
	"sync"

	gssh "golang.org/x/crypto/ssh"
)

// TerminalStream owns a remote PTY and its SSH transport, independent of the
// agent host's OS and stdin. Closing it cancels blocked IO and the remote shell.
type TerminalStream struct {
	session *gssh.Session
	client  *Client
	input   io.WriteCloser
	output  *io.PipeReader
	writer  *io.PipeWriter
	once    sync.Once
}

func (c *Client) OpenTerminal(ctx context.Context, cols, rows int) (*TerminalStream, error) {
	if cols < 20 || cols > 300 || rows < 5 || rows > 150 {
		return nil, sessionError("terminal_size", errors.New("invalid terminal size"))
	}
	if c.conn == nil {
		return nil, sessionError("session_open", errors.New("not connected"))
	}
	if err := ctx.Err(); err != nil {
		return nil, sessionError("session_open", err)
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	conn := c.conn
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			// Close only the transport here; the owner releases Client resources.
			// Mutating c.conn from this goroutine races with session setup/Close.
			conn.Close()
		case <-done:
		}
	}()
	defer func() { close(done); <-stopped }()
	wrap := func(stage string, err error) error {
		if ctx.Err() != nil {
			err = errors.Join(err, ctx.Err())
		}
		return sessionError(stage, err)
	}
	sess, err := conn.NewSession()
	if err != nil {
		return nil, wrap("session_open", err)
	}
	fail := func(err error) (*TerminalStream, error) { sess.Close(); return nil, err }
	if err = sess.RequestPty("xterm-256color", rows, cols, gssh.TerminalModes{gssh.ECHO: 1, gssh.TTY_OP_ISPEED: 38400, gssh.TTY_OP_OSPEED: 38400}); err != nil {
		return fail(wrap("pty_request", err))
	}
	input, err := sess.StdinPipe()
	if err != nil {
		return fail(wrap("stdin_pipe", err))
	}
	reader, writer := io.Pipe()
	sess.Stdout = writer
	sess.Stderr = writer
	if err = sess.Shell(); err != nil {
		reader.Close()
		writer.Close()
		return fail(wrap("shell_start", err))
	}
	t := &TerminalStream{session: sess, client: c, input: input, output: reader, writer: writer}
	go func() { err := sess.Wait(); writer.CloseWithError(err) }()
	return t, nil
}
func (t *TerminalStream) Read(b []byte) (int, error)  { return t.output.Read(b) }
func (t *TerminalStream) Write(b []byte) (int, error) { return t.input.Write(b) }
func (t *TerminalStream) Resize(cols, rows int) error {
	if cols < 20 || cols > 300 || rows < 5 || rows > 150 {
		return errors.New("invalid terminal size")
	}
	return t.session.WindowChange(rows, cols)
}
func (t *TerminalStream) Close() error {
	t.once.Do(func() { t.output.Close(); t.writer.Close(); t.input.Close(); t.session.Close(); t.client.Close() })
	return nil
}
