package cloudagent

import (
	"github.com/charmbracelet/x/conpty"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

type nativeTerminal struct {
	*conpty.ConPty
	process, job windows.Handle
	once         sync.Once
}

func startTerminal(cols, rows int) (terminal, error) {
	shell, e := exec.LookPath("powershell.exe")
	if e != nil {
		return nil, e
	}
	tty, e := conpty.New(cols, rows, 0)
	if e != nil {
		return nil, e
	}
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		tty.Close()
		return nil, e
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); e != nil {
		windows.CloseHandle(job)
		tty.Close()
		return nil, e
	}
	_, handle, e := tty.Spawn(shell, []string{shell, "-NoLogo", "-NoProfile"}, &syscall.ProcAttr{Env: os.Environ()})
	if e != nil {
		windows.CloseHandle(job)
		tty.Close()
		return nil, e
	}
	process := windows.Handle(handle)
	if e = windows.AssignProcessToJobObject(job, process); e != nil {
		windows.TerminateProcess(process, 1)
		windows.CloseHandle(process)
		windows.CloseHandle(job)
		tty.Close()
		return nil, e
	}
	return &nativeTerminal{ConPty: tty, process: process, job: job}, nil
}
func (t *nativeTerminal) Resize(cols, rows int) error { return t.ConPty.Resize(cols, rows) }
func (t *nativeTerminal) Close() error {
	t.once.Do(func() {
		windows.CloseHandle(t.job)
		windows.TerminateProcess(t.process, 1)
		windows.CloseHandle(t.process)
		t.ConPty.Close()
	})
	return nil
}
