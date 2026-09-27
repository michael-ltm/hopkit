package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/michael-ltm/sshm/internal/keys"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func addKeyPassphraseFlag(cmd *cobra.Command) {
	cmd.Flags().String("passphrase-file", "", "use a private, user-managed key passphrase file instead of automatic device protection")
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
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		if err := localCredentialStore(configPath()).Ensure(ctx); err != nil {
			return "", err
		}
		b = make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		defer clear(b)
		return base64.RawStdEncoding.EncodeToString(b), nil
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
