package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func agentAuth() (gssh.AuthMethod, io.Closer, error) {
	conn, err := dialAgent()
	if err != nil {
		return nil, nil, err
	}
	return gssh.PublicKeysCallback(agent.NewClient(conn).Signers), conn, nil
}

// agentSignerFor returns the agent-backed signer whose public key matches
// want. Unlike agentAuth it offers only that one identity, so a server's
// MaxAuthTries is never exhausted by unrelated keys. The returned closer
// holds the agent connection and must stay open for the connection's
// lifetime.
func agentSignerFor(want gssh.PublicKey) (gssh.Signer, io.Closer, error) {
	conn, err := dialAgent()
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("set ssh-agent list deadline: %w", err)
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("list ssh-agent identities: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("clear ssh-agent list deadline: %w", err)
	}
	wantBlob := want.Marshal()
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), wantBlob) {
			return s, conn, nil
		}
	}
	conn.Close()
	return nil, nil, errors.New("ssh-agent holds no matching identity (ssh-add the key first)")
}
