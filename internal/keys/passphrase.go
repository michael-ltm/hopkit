package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// RandomPassphrase returns a high-entropy passphrase (32 bytes of crypto/rand
// rendered as unpadded URL-safe base64). It is intended to be stored in an OS
// keystore, not memorised, so it favours entropy over readability.
func RandomPassphrase() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
