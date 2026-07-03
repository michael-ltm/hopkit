package keys

import (
	"fmt"
	"os"
	"path/filepath"
)

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
	return rp, nil
}
