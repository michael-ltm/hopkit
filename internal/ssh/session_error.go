package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// SessionError identifies a failure after SSH authentication. Stage and Code
// are safe enums; Cause is local diagnostic detail and must not be sent to a relay.
type SessionError struct {
	Stage string
	Code  string
	Cause error
}

func (e *SessionError) Error() string {
	prefix := map[string]string{
		"session_open": "new session", "terminal_size": "terminal size",
		"local_tty": "make raw tty", "pty_request": "request pty",
		"stdin_pipe": "open stdin pipe", "shell_start": "start shell",
		"command_start": "start interactive command",
	}[e.Stage]
	return fmt.Sprintf("%s: %v", prefix, e.Cause)
}

func (e *SessionError) Unwrap() error { return e.Cause }

func sessionError(stage string, cause error) error {
	code := stage + "_failed"
	var timeout net.Error
	switch {
	case errors.Is(cause, context.Canceled):
		code = "cancelled"
	case errors.Is(cause, context.DeadlineExceeded) || (errors.As(cause, &timeout) && timeout.Timeout()):
		code = "timeout"
	// x/crypto/ssh has no exported sentinel for a negative pty-req reply.
	// Match its exact error, never a substring (EOF is not policy denial).
	case stage == "pty_request" && cause.Error() == "ssh: pty-req failed":
		code = "pty_denied"
	}
	return &SessionError{Stage: stage, Code: code, Cause: cause}
}
