package localstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func prepareDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("local credential directory must not be a symlink")
	}
	return protect(path, true)
}
func readPrivate(path string, max int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, ErrCorrupt
	}
	if e = checkPrivate(st); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return nil, ErrCorrupt
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if len(b) > int(max) {
		clear(b)
		return nil, ErrCorrupt
	}
	return b, e
}
func writePrivate(path string, b []byte) error {
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() {
			return errors.New("refusing non-regular credential file")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = protect(f.Name(), false); e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
