package keys

import (
	"bytes"
	"errors"
	"io"
	"os"
	"runtime"
)

// ReadPassphraseFile reads a user-managed secret without creating a recovery
// copy. Callers must clear the returned bytes when finished and never log them.
func ReadPassphraseFile(path string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("passphrase files are not supported on Windows until ACL validation is available; use the local interactive CLI passphrase prompt")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("passphrase file must be a regular file, not a symlink")
	}
	f, err := openPassphraseFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, info) || !info.Mode().IsRegular() {
		return nil, errors.New("passphrase file changed while opening")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("passphrase file must be private (chmod 600)")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		clear(b)
		return nil, err
	}
	if len(b) > 1024 {
		clear(b)
		return nil, errors.New("passphrase file exceeds 1024 bytes")
	}
	pass := bytes.TrimSuffix(b, []byte("\n"))
	pass = bytes.TrimSuffix(pass, []byte("\r"))
	if len(pass) == 0 || bytes.ContainsAny(pass, "\r\n\x00") {
		clear(b)
		return nil, errors.New("passphrase file must contain one nonempty line")
	}
	return pass, nil
}
