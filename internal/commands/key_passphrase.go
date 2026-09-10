package commands

import (
	"fmt"

	"github.com/michael-ltm/sshm/internal/keys"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func addKeyPassphraseFlag(cmd *cobra.Command) {
	cmd.Flags().String("passphrase-file", "", "read a private, user-managed key passphrase file; otherwise prompt without echo")
}

func keyPassphrase(cmd *cobra.Command) (string, error) {
	path, _ := cmd.Flags().GetString("passphrase-file")
	var b []byte
	var err error
	if path != "" {
		path, err = sshpkg.ExpandHome(path)
		if err != nil {
			return "", err
		}
		b, err = keys.ReadPassphraseFile(path)
	} else {
		b, err = cloudSecret(cmd, "New SSH key passphrase (keep in your password manager)", true)
	}
	defer clear(b)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", fmt.Errorf("key passphrase must not be empty; use --no-encrypt explicitly for an unencrypted key")
	}
	return string(b), nil
}
