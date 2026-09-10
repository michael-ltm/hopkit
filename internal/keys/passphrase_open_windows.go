//go:build windows

package keys

import (
	"errors"
	"os"
)

func openPassphraseFile(string) (*os.File, error) {
	return nil, errors.New("passphrase files are not supported on Windows; use the local interactive CLI passphrase prompt")
}
