package ssh

import (
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/muesli/cancelreader"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// AttachInteractive opens an interactive shell on the connected client,
// wiring the local TTY to the remote PTY. Returns when the user logs out.
func (c *Client) AttachInteractive() error {
	return c.attachInteractive("")
}

// AttachInteractiveCommand runs one command under a remote PTY. It is used
// for terminal-owned sensitive workflows such as passwd, so secret input goes
// directly from the user's keyboard to the remote server.
func (c *Client) AttachInteractiveCommand(command string) error {
	if command == "" {
		return errors.New("interactive command is required")
	}
	return c.attachInteractive(command)
}

func (c *Client) attachInteractive(command string) error {
	if c.conn == nil {
		return sessionError("session_open", errors.New("not connected"))
	}
	sess, err := c.conn.NewSession()
	if err != nil {
		return sessionError("session_open", err)
	}
	defer sess.Close()

	fd := int(os.Stdin.Fd())
	// TODO(v0.3): handle SIGWINCH to send window-change requests on resize.
	w, h := 80, 24
	var oldState *term.State
	if term.IsTerminal(fd) {
		oldState, err = term.MakeRaw(fd)
		if err != nil {
			return sessionError("local_tty", err)
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
		return sessionError("pty_request", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return sessionError("stdin_pipe", err)
	}
	var reader io.Reader = os.Stdin
	var cancellable cancelreader.CancelReader
	stat, _ := os.Stdin.Stat()
	// Regular files and /dev/null cannot be registered with epoll. They do not
	// need an interruptible terminal read; preserve redirected stdin support.
	// On Windows cancelreader opens CONIN$, so redirected pipes must keep
	// their original reader instead of being replaced by console input.
	if term.IsTerminal(fd) || (runtime.GOOS != "windows" && stat != nil && stat.Mode()&os.ModeNamedPipe != 0) {
		cancellable, err = cancelreader.NewReader(os.Stdin)
		if err != nil {
			return sessionError("stdin_pipe", err)
		}
		defer cancellable.Close()
		defer cancellable.Cancel()
		reader = cancellable
	}
	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	if command == "" {
		if err := sess.Shell(); err != nil {
			return sessionError("shell_start", err)
		}
	} else if err := sess.Start(command); err != nil {
		return sessionError("command_start", err)
	}
	// Do not leave a reader blocked on the local terminal after setup fails or
	// the remote program exits. Closing stdin also unblocks a pending SSH write.
	copied := make(chan struct{})
	go func() { defer close(copied); _, _ = io.Copy(stdin, reader) }()
	defer func() {
		_ = sess.Close()
		if cancellable != nil && cancellable.Cancel() {
			<-copied
		}
	}()
	return sess.Wait()
}

func getTerm() string {
	if t := os.Getenv("TERM"); t != "" {
		return t
	}
	return "xterm-256color"
}
