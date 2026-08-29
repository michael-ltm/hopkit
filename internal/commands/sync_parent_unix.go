//go:build !windows

package commands

import (
	"os"
	"path/filepath"
)

func syncParentDir(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
