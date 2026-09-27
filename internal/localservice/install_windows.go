//go:build windows

package localservice

import (
	"errors"
	"os/exec"
	"syscall"
)

func installWindows(configPath, binary, path string) error {
	if !validPath(binary) || !validPath(configPath) {
		return errors.New("service requires absolute paths without control characters")
	}
	sid, e := currentSID()
	if e != nil {
		return e
	}
	args := "--config " + syscall.EscapeArg(configPath) + " service run --supervise"
	data := renderWindowsTask(sid, binary, args)
	// schtasks accepts UTF-8 XML with an explicit UTF-8 declaration.
	if e = privateWrite(path, []byte(data)); e != nil {
		return e
	}
	if e = exec.Command("schtasks.exe", "/Create", "/F", "/TN", "sshm-local-"+instance(configPath), "/XML", path).Run(); e != nil {
		return errors.New("could not register local service startup")
	}
	if e = exec.Command("schtasks.exe", "/Run", "/TN", "sshm-local-"+instance(configPath)).Run(); e != nil {
		return errors.New("startup registered but local service could not be started")
	}
	return nil
}
