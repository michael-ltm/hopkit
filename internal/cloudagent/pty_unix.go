//go:build !windows

package cloudagent

import (
	"github.com/creack/pty"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type nativeTerminal struct {
	*os.File
	cmd  *exec.Cmd
	once sync.Once
}

func startTerminal(cols, rows int) (terminal, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-l")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	if home, e := os.UserHomeDir(); e == nil {
		cmd.Dir = home
	}
	f, e := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if e != nil {
		return nil, e
	}
	t := &nativeTerminal{File: f, cmd: cmd}
	go cmd.Wait()
	return t, nil
}
func (t *nativeTerminal) Resize(cols, rows int) error {
	return pty.Setsize(t.File, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}
func (t *nativeTerminal) Close() error {
	t.once.Do(func() { _ = syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL); _ = t.File.Close() })
	return nil
}
