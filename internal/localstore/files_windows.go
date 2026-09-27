//go:build windows

package localstore

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"time"
)

func protect(path string, _ bool) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	system, e := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if e != nil {
		return e
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, sid := range []*windows.SID{user.User.Sid, system} {
		entries = append(entries, windows.EXPLICIT_ACCESS{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)}})
	}
	acl, e := windows.ACLFromEntries(entries, nil)
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func checkPrivate(os.FileInfo) error { return nil } // DPAPI enforces the user decryption boundary; writes use a private DACL.
func syncDir(string) error           { return nil }
func lockFile(ctx context.Context, path string) (func(), error) {
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return nil, ErrCorrupt
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = protect(path, false); e != nil {
		f.Close()
		return nil, e
	}
	ov := new(windows.Overlapped)
	for {
		e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ov)
		if e == nil {
			break
		}
		if !errors.Is(e, windows.ERROR_LOCK_VIOLATION) {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ov); _ = f.Close() }, nil
}
