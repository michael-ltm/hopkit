package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"

	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// AttachInteractive opens an interactive shell on the connected client,
// wiring the local TTY to the remote PTY. Returns when the user logs out.
func (c *Client) AttachInteractive() error {
	if c.conn == nil {
		return errors.New("not connected")
	}
	sess, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	fd := int(os.Stdin.Fd())
	// TODO(v0.3): handle SIGWINCH to send window-change requests on resize.
	w, h := 80, 24
	var oldState *term.State
	if term.IsTerminal(fd) {
		oldState, err = term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("make raw tty: %w", err)
		}
		defer term.Restore(fd, oldState)
		if width, height, err := term.GetSize(fd); err == nil {
			w, h = width, height
		}
	}

	modes := gssh.TerminalModes{
		gssh.ECHO:          1,
		gssh.TTY_OP_ISPEED: 14400,
		gssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty(getTerm(), h, w, modes); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("open stdin pipe: %w", err)
	}
	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	go func() { _, _ = io.Copy(stdin, os.Stdin) }()

	if err := sess.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}
	return sess.Wait()
}

func getTerm() string {
	if t := os.Getenv("TERM"); t != "" {
		return t
	}
	return "xterm-256color"
}
