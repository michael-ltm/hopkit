//go:build !windows

package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// agentPaths returns the current user's agent candidates in preference order.
// An explicitly supplied socket remains first, but a dead inherited value must
// not prevent GUI/MCP processes from recovering through the platform or managed
// SSHM agent.
func agentPaths() []string {
	paths := make([]string, 0, 3)
	add := func(path string) {
		if path == "" || slicesContains(paths, path) {
			return
		}
		paths = append(paths, path)
	}
	add(os.Getenv("SSH_AUTH_SOCK"))
	add(platformAgentSocket())
	add(ownAgentSocket(ManagedAgentPath()))
	return paths
}

func slicesContains(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}

func explicitAgentConfigured() bool { return os.Getenv("SSH_AUTH_SOCK") != "" }

func dialAgentAt(sock string) (net.Conn, error) { return net.DialTimeout("unix", sock, 5*time.Second) }

func dialAgent() (net.Conn, error) {
	var errs []error
	for _, sock := range agentPaths() {
		conn, err := dialAgentAt(sock)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", sock, err))
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("connect to ssh-agent: %w", errors.Join(errs...))
	}
	return nil, errors.New("SSH_AUTH_SOCK not set (no ssh-agent running)")
}
