//go:build windows

package ssh

import (
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
// overrides the target when it names another pipe (e.g. gpg4win's agent);
// cygwin-style socket paths are not dialable from Go and are ignored.
func dialAgent() (net.Conn, error) {
	pipe := windowsAgentPipe
	if sock := os.Getenv("SSH_AUTH_SOCK"); strings.HasPrefix(sock, `\\.\pipe\`) {
		pipe = sock
	}
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to ssh-agent pipe %s (is the \"OpenSSH Authentication Agent\" service running?): %w", pipe, err)
	}
	return conn, nil
}
