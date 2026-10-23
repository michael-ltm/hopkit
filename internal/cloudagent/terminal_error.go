package cloudagent

import (
	"errors"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

func targetErrorPayload(err error) cloudsync.ShellPayload {
	p := cloudsync.ShellPayload{Type: "error", Data: targetError(err)}
	var session *sshpkg.SessionError
	if errors.As(err, &session) {
		d := &cloudsync.TerminalDiagnostics{SSHAuthenticated: true}
		// Enumerate both fields; never serialize an error-supplied arbitrary string.
		switch session.Stage {
		case "terminal_size", "session_open":
		case "pty_request":
			d.PTYRequested = true
		case "stdin_pipe", "shell_start", "command_start":
			d.PTYRequested, d.PTYGranted = true, true
		default:
			return p
		}
		d.Stage = session.Stage
		switch session.Code {
		case session.Stage + "_failed", "cancelled", "timeout":
			d.ReasonCode = session.Code
		case "pty_denied":
			if session.Stage != "pty_request" {
				return p
			}
			d.ReasonCode, d.SuggestedAction = "pty_denied", "explicit_exec"
		default:
			return p
		}
		p.Diagnostics = d
	} else if p.Data == "ssh_authentication" {
		p.Diagnostics = &cloudsync.TerminalDiagnostics{Stage: "authentication", ReasonCode: "authentication_failed"}
	}
	return p
}
