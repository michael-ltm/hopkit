package ssh

import (
	"errors"
	"net"
	"os"

	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func agentAuth() (gssh.AuthMethod, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("SSH_AUTH_SOCK not set (no ssh-agent running)")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	return gssh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
}
