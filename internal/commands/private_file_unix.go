//go:build !windows

package commands

import "os"

func protectPrivateFile(path string) error {
	return os.Chmod(path, 0o600)
}
