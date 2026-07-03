// Package keys manages SSH keypair generation and remote installation.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	gssh "golang.org/x/crypto/ssh"
)

// GenerateED25519 writes a new unencrypted ed25519 keypair. See
// GenerateED25519Encrypted for the passphrase-protected form.
func GenerateED25519(keyPath, comment string) (pubLine string, err error) {
	return GenerateED25519Encrypted(keyPath, comment, "")
}

// GenerateED25519Encrypted writes a new ed25519 private key to keyPath
// (mode 0600) and its public key to keyPath+".pub" (mode 0644), returning the
// OpenSSH public-key line. When passphrase != "" the private key is encrypted
// with it. Refuses to overwrite an existing private key.
func GenerateED25519Encrypted(keyPath, comment, passphrase string) (pubLine string, err error) {
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

	var pemBlock *pem.Block
	var mErr error
	if passphrase == "" {
		pemBlock, mErr = gssh.MarshalPrivateKey(priv, comment)
	} else {
		pemBlock, mErr = gssh.MarshalPrivateKeyWithPassphrase(priv, comment, []byte(passphrase))
	}
	if mErr != nil {
		return "", fmt.Errorf("marshal private key: %w", mErr)
	}
	if err = os.WriteFile(keyPath, encodePEM(pemBlock), 0o600); err != nil {
		return "", fmt.Errorf("write private key %s: %w", keyPath, err)
	}
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
	pubLine = pubLine[:len(pubLine)-1] + " " + comment + "\n"
	if err = os.WriteFile(keyPath+".pub", []byte(pubLine), 0o644); err != nil {
		err = fmt.Errorf("write public key %s: %w", keyPath+".pub", err)
		return "", err
	}
	return pubLine, nil
}

// RemoveGenerated removes the private key, its .pub file, and any
// keyPath+".passphrase" recovery file, ignoring errors from each removal.
//
// Callers use this when a step *after* GenerateED25519Encrypted has already
// succeeded fails fatally (e.g. WriteRecovery or a config save) — without
// this cleanup, the key file would be left orphaned on disk and a retry
// would hit GenerateED25519Encrypted's "key already exists" refusal,
// wedging the caller permanently.
func RemoveGenerated(keyPath string) {
	os.Remove(keyPath)
	os.Remove(keyPath + ".pub")
	os.Remove(keyPath + ".passphrase")
}
