package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errAgentNoMatchingIdentity = errors.New("ssh-agent holds no matching identity (ssh-add the key first)")

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
	var lastErr error
	seen := map[string]bool{}
	paths := agentPaths()
	for i, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		conn, err := dialAgentAt(path)
		if err != nil {
			lastErr = err
			continue
		}
		signer, closer, err := signerFromAgent(conn, want)
		if err == nil {
			return signer, closer, nil
		}
		lastErr = err
		// A reachable explicitly selected agent is authoritative. Only a failed
		// endpoint dial should fall through to the platform/managed candidates;
		// protocol and identity errors must remain tied to the selected agent.
		if i == 0 && explicitAgentConfigured() {
			return nil, nil, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no SSH agent available; start the platform agent and load the key")
	}
	return nil, nil, lastErr
}

// AgentSignerForPublicKey returns an agent-backed signer only for the exact
// public key supplied by the caller. It never exposes the private key or its
// passphrase and is used when an encrypted vault copy is unavailable but the
// user's OS agent has already unlocked the same identity.
func AgentSignerForPublicKey(want gssh.PublicKey) (gssh.Signer, io.Closer, error) {
	if want == nil {
		return nil, nil, errors.New("public key is required")
	}
	return agentSignerFor(want)
}

func signerFromAgent(conn net.Conn, want gssh.PublicKey) (gssh.Signer, io.Closer, error) {
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
	return nil, nil, errAgentNoMatchingIdentity
}
