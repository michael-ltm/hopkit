// Package keys manages SSH keypair generation and remote installation.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"

	gssh "golang.org/x/crypto/ssh"
)

// GenerateED25519 writes a new ed25519 private key to keyPath (mode 0600)
// and its public key to keyPath+".pub" (mode 0644). Returns the public-key
// line (OpenSSH format). Refuses to overwrite an existing private key.
func GenerateED25519(keyPath, comment string) (pubLine string, err error) {
	// Reject control characters in the comment so they can't smuggle extra
	// lines into authorized_keys when the returned pub line is appended there.
	comment = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, comment)

	if _, err = os.Stat(keyPath); err == nil {
		return "", fmt.Errorf("key already exists at %s (delete it first to regenerate)", keyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519: %w", err)
	}

	pemBlock, err2 := gssh.MarshalPrivateKey(priv, comment)
	if err2 != nil {
		return "", fmt.Errorf("marshal private key: %w", err2)
	}
	if err = os.WriteFile(keyPath, encodePEM(pemBlock), 0o600); err != nil {
		return "", fmt.Errorf("write private key %s: %w", keyPath, err)
	}

	// Remove the private key file if any subsequent step fails.
	defer func() {
		if err != nil {
			os.Remove(keyPath)
		}
	}()

	sshPub, err2 := gssh.NewPublicKey(pub)
	if err2 != nil {
		err = fmt.Errorf("marshal public key: %w", err2)
		return "", err
	}
	pubLine = string(gssh.MarshalAuthorizedKey(sshPub))
	pubLine = pubLine[:len(pubLine)-1] + " " + comment + "\n" // append comment
	if err = os.WriteFile(keyPath+".pub", []byte(pubLine), 0o644); err != nil {
		err = fmt.Errorf("write public key %s: %w", keyPath+".pub", err)
		return "", err
	}
	return pubLine, nil
}
