//go:build !windows

package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// dialAgent connects to the ssh-agent named by SSH_AUTH_SOCK.
func agentPaths() []string {
	paths := []string{os.Getenv("SSH_AUTH_SOCK")}
	if paths[0] == "" {
		paths = []string{platformAgentSocket(), ownAgentSocket(ManagedAgentPath())}
	}
	return paths
}

func dialAgentAt(sock string) (net.Conn, error) { return net.DialTimeout("unix", sock, 5*time.Second) }

func dialAgent() (net.Conn, error) {
	var lastErr error
	for _, sock := range agentPaths() {
		if sock == "" {
			continue
		}
		conn, err := dialAgentAt(sock)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("connect to ssh-agent: %w", lastErr)
	}
	return nil, errors.New("SSH_AUTH_SOCK not set (no ssh-agent running)")
}
