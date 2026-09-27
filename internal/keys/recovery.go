package keys

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// ReadRecovery reads only the configured key's existing private recovery
// sidecar. Legacy WriteRecovery headers are accepted here, not by the strict
// user-managed ReadPassphraseFile API. Callers must clear the result after use.
func ReadRecovery(keyPath string) ([]byte, error) {
	b, err := readPrivatePassphraseFile(keyPath + ".passphrase")
	if err != nil {
		return nil, err
	}
	defer clear(b)
	pass, err := parsePassphraseLine(b)
	if err == nil {
		return bytes.Clone(pass), nil
	}
	// Only WriteRecovery's two known headers are comments. A literal secret
	// beginning with '#' must remain intact, including after those headers.
	first, rest, firstLine := bytes.Cut(b, []byte("\n"))
	second, body, secondLine := bytes.Cut(rest, []byte("\n"))
	if !firstLine || !secondLine ||
		!bytes.HasPrefix(bytes.TrimSuffix(first, []byte("\r")), []byte("# sshm recovery — passphrase for ")) ||
		!bytes.Equal(bytes.TrimSuffix(second, []byte("\r")), []byte("# move this into your password manager, then delete this file")) {
		return nil, err
	}
	pass, err = parsePassphraseLine(body)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(pass), nil
}

// WriteRecovery writes the key's passphrase to keyPath+".passphrase" (mode
// 0600), refusing to overwrite. This is the one-time recovery copy the user
// should move into a password manager and then delete.
func WriteRecovery(keyPath, passphrase string) (string, error) {
	rp := keyPath + ".passphrase"
	if _, err := os.Stat(rp); err == nil {
		return "", fmt.Errorf("recovery file already exists at %s", rp)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	body := fmt.Sprintf("# sshm recovery — passphrase for %s\n# move this into your password manager, then delete this file\n%s\n",
		filepath.Base(keyPath), passphrase)
	if err := os.WriteFile(rp, []byte(body), 0o600); err != nil {
		return "", fmt.Errorf("write recovery %s: %w", rp, err)
	}
	if err := protectPrivateFile(rp); err != nil {
		_ = os.Remove(rp)
		return "", fmt.Errorf("protect recovery %s: %w", rp, err)
	}
	return rp, nil
}
