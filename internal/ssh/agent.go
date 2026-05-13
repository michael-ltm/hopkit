package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func agentAuth() (gssh.AuthMethod, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK not set (no ssh-agent running)")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to ssh-agent: %w", err)
	}
	return gssh.PublicKeysCallback(agent.NewClient(conn).Signers), conn, nil
}
