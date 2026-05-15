package ssh

import (
	"errors"
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
		return err
	}
	defer sess.Close()

	fd := int(os.Stdin.Fd())
	w, h := 80, 24
	var oldState *term.State
	if term.IsTerminal(fd) {
		oldState, err = term.MakeRaw(fd)
		if err != nil {
			return err
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
		return err
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	go func() { _, _ = io.Copy(stdin, os.Stdin) }()

	if err := sess.Shell(); err != nil {
		return err
	}
	return sess.Wait()
}

func getTerm() string {
	if t := os.Getenv("TERM"); t != "" {
		return t
	}
	return "xterm-256color"
}
