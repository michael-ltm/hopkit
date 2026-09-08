package ssh

import (
	"context"
	"errors"
	gssh "golang.org/x/crypto/ssh"
	"io"
	"sync"
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
		return nil, errors.New("invalid terminal size")
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	defer close(done)
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*TerminalStream, error) { sess.Close(); return nil, err }
	if err = sess.RequestPty("xterm-256color", rows, cols, gssh.TerminalModes{gssh.ECHO: 1, gssh.TTY_OP_ISPEED: 38400, gssh.TTY_OP_OSPEED: 38400}); err != nil {
		return fail(err)
	}
	input, err := sess.StdinPipe()
	if err != nil {
		return fail(err)
	}
	reader, writer := io.Pipe()
	sess.Stdout = writer
	sess.Stderr = writer
	if err = sess.Shell(); err != nil {
		reader.Close()
		writer.Close()
		return fail(err)
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
