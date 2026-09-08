//go:build !windows && !darwin

package ssh

import (
	"os"
	"path/filepath"
)

// Preserve the original SSHM agent used by Linux shell installations. Only a
// socket owned by this user is eligible; never scan other users' agents.
func platformAgentSocket() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return ownAgentSocket(filepath.Join(home, ".ssh", "sshm-agent.sock"))
}
