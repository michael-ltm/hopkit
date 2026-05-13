// Package keys manages SSH keypair generation and remote installation.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	gssh "golang.org/x/crypto/ssh"
)

// GenerateED25519 writes a new ed25519 private key to keyPath (mode 0600)
// and its public key to keyPath+".pub" (mode 0644). Returns the public-key
// line (OpenSSH format). Refuses to overwrite an existing private key.
func GenerateED25519(keyPath, comment string) (string, error) {
	if _, err := os.Stat(keyPath); err == nil {
		return "", fmt.Errorf("key already exists at %s (delete it first to regenerate)", keyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519: %w", err)
	}

	pemBlock, err := gssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	if err := os.WriteFile(keyPath, encodePEM(pemBlock), 0o600); err != nil {
		return "", err
	}

	sshPub, err := gssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	pubLine := string(gssh.MarshalAuthorizedKey(sshPub))
	pubLine = pubLine[:len(pubLine)-1] + " " + comment + "\n" // append comment
	if err := os.WriteFile(keyPath+".pub", []byte(pubLine), 0o644); err != nil {
		return "", err
	}
	return pubLine, nil
}
