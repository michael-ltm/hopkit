//go:build windows

package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// windowsAgentPipe is the named pipe served by the Win32-OpenSSH
// "OpenSSH Authentication Agent" service.
const windowsAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to the Windows OpenSSH agent named pipe. SSH_AUTH_SOCK
// is tried first when it names another pipe (e.g. gpg4win's agent); cygwin-
// style socket paths are not dialable from Go and are ignored. A failed
// explicit pipe falls back to the Windows OpenSSH service pipe.
func agentPaths() []string {
	paths := make([]string, 0, 2)
	if sock := os.Getenv("SSH_AUTH_SOCK"); strings.HasPrefix(sock, `\\.\pipe\`) {
		paths = append(paths, sock)
	}
	if len(paths) == 0 || paths[0] != windowsAgentPipe {
		paths = append(paths, windowsAgentPipe)
	}
	return paths
}

func explicitAgentConfigured() bool {
	return strings.HasPrefix(os.Getenv("SSH_AUTH_SOCK"), `\\.\pipe\`)
}

func dialAgent() (net.Conn, error) {
	var errs []error
	for _, pipe := range agentPaths() {
		conn, err := dialAgentAt(pipe)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("connect to ssh-agent: %w", errors.Join(errs...))
	}
	return nil, errors.New("SSH_AUTH_SOCK not set (no ssh-agent running)")
}

func dialAgentAt(pipe string) (net.Conn, error) {
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to ssh-agent pipe %s (is the \"OpenSSH Authentication Agent\" service running?): %w", pipe, err)
	}
	return conn, nil
}
