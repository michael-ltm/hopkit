//go:build windows

package localservice

import (
	"context"
	"errors"
	"github.com/Microsoft/go-winio"
	"github.com/michael-ltm/sshm/internal/localstore"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func currentSID() (string, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", e
	}
	return u.User.Sid.String(), nil
}
func SocketPath(path string) string {
	sid, _ := currentSID()
	return `\\.\pipe\sshm-` + sid + "-" + instance(path)
}
func prepareRuntime(path string) error {
	dir := filepath.Dir(localstore.New(path).Path())
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	return protectFile(dir)
}
func processLock(path string) (func(), error) {
	name := localstore.New(path).ConfigPath + ".local/service.lock"
	if st, e := os.Lstat(name); e == nil && !st.Mode().IsRegular() {
		return nil, errors.New("unsafe local service lock")
	}
	f, e := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = protectFile(name); e != nil {
		f.Close()
		return nil, e
	}
	ov := new(windows.Overlapped)
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ov); e != nil {
		f.Close()
		return nil, ErrRunning
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ov); _ = f.Close() }, nil
}
func listenEndpoint(path string) (net.Listener, error) {
	sid, e := currentSID()
	if e != nil {
		return nil, e
	}
	return winio.ListenPipe(SocketPath(path), &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")"})
}
func dialEndpoint(ctx context.Context, path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	return winio.DialPipeContext(ctx, path)
}
func sameUser(net.Conn) bool { return true } // The named pipe DACL permits only the current user's SID.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS, HideWindow: true}
}
func protectFile(path string) error {
	sid, e := currentSID()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + sid + ")")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
