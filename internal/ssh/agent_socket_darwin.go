//go:build darwin

package ssh

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// GUI-launched MCP processes may not inherit SSH_AUTH_SOCK. Consult only the
// current user's launchd environment; never search other users' agents or load
// a key/passphrase automatically. An explicit SSH_AUTH_SOCK takes precedence.
func platformAgentSocket() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "getenv", "SSH_AUTH_SOCK").Output()
	if err != nil {
		return ""
	}
	return ownAgentSocket(strings.TrimSpace(string(out)))
}
