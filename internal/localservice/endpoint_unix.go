//go:build !windows

package localservice

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func SocketPath(configPath string) string {
	return filepath.Join(runtimeDir(), instance(configPath)+".sock")
}
func runtimeDir() string { return filepath.Join("/tmp", fmt.Sprintf("sshm-agent-%d", os.Getuid())) }
func owned(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Getuid())
}
func prepareRuntime(string) error {
	dir := runtimeDir()
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !owned(st) || st.Mode().Perm() != 0700 {
		return errors.New("unsafe local service runtime directory")
	}
	return nil
}
func processLock(configPath string) (func(), error) {
	path := SocketPath(configPath) + ".lock"
	fd, e := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, errors.New("unsafe local service lock")
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || !owned(st) || st.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("unsafe local service lock")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, ErrRunning
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
}
func listenEndpoint(configPath string) (net.Listener, error) {
	path := SocketPath(configPath)
	if st, e := os.Lstat(path); e == nil {
		if st.Mode()&os.ModeSocket == 0 || !owned(st) || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("unsafe local service socket")
		}
		if active(configPath) {
			return nil, ErrRunning
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	ln, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		ln.Close()
		return nil, e
	}
	return ln, nil
}
func dialEndpoint(ctx context.Context, path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
func detach(cmd *exec.Cmd)          { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func protectFile(path string) error { return os.Chmod(path, 0600) }
