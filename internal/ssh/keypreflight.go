package ssh

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	gssh "golang.org/x/crypto/ssh"
)

// CheckKeyPairUsable verifies that path and its sibling .pub file describe the
// same key and that sshm can obtain a working signer for it right now. It
// returns the exact public-key line that was checked so pairing publishes that
// same value instead of re-reading a possibly changed .pub file. For an
// encrypted private key this exercises the exact ssh-agent/keychain-backed
// signing path used by Dial, without exposing or persisting the passphrase.
func CheckKeyPairUsable(path string) (string, error) {
	expanded, err := ExpandHome(path)
	if err != nil {
		return "", err
	}

	signer, closer, err := loadKeySigner(expanded)
	if err != nil {
		return "", err
	}
	if closer != nil {
		defer closer.Close()
	}

	publicData, err := os.ReadFile(expanded + ".pub")
	if err != nil {
		return "", fmt.Errorf("read public key %s.pub: %w", expanded, err)
	}
	expected, _, _, rest, err := gssh.ParseAuthorizedKey(publicData)
	if err != nil {
		return "", fmt.Errorf("parse public key %s.pub: %w", expanded, err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return "", fmt.Errorf("public key %s.pub must contain exactly one key", expanded)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), expected.Marshal()) {
		return "", fmt.Errorf("private key %s does not match %s.pub", expanded, expanded)
	}
	if conn, ok := closer.(net.Conn); ok {
		if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return "", fmt.Errorf("set ssh-agent signing deadline: %w", err)
		}
	}

	challenge := []byte("sshm pair key signing preflight")
	signature, err := signer.Sign(rand.Reader, challenge)
	if err != nil {
		return "", fmt.Errorf("sign with key %s: %w", expanded, err)
	}
	if err := signer.PublicKey().Verify(challenge, signature); err != nil {
		return "", fmt.Errorf("verify signature from key %s: %w", expanded, err)
	}
	return strings.TrimSpace(string(publicData)), nil
}
