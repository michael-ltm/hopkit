//go:build !windows

package keys

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestOpenPassphraseFileCannotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swapped-file")
	require.NoError(t, unix.Mkfifo(path, 0600))
	done := make(chan error, 1)
	go func() {
		f, err := openPassphraseFile(path)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("passphrase opener blocked on FIFO")
	}
}

func TestOpenPassphraseFileRejectsSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	target, path := filepath.Join(dir, "target"), filepath.Join(dir, "symlink")
	require.NoError(t, os.WriteFile(target, []byte("private managed secret"), 0600))
	require.NoError(t, os.Symlink(target, path))
	f, err := openPassphraseFile(path)
	if f != nil {
		f.Close()
	}
	require.Error(t, err)
}
