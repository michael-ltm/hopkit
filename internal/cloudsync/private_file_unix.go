//go:build !windows

package cloudsync

import "os"

func protectPrivateFile(path string) error {
	return os.Chmod(path, 0o600)
}
