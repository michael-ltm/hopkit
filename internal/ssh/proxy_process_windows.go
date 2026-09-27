//go:build windows

package ssh

import (
	"context"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func prepareProxyProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
}

func terminateProxyProcess(cmd *exec.Cmd) {
	// Windows process groups do not provide Unix-style group termination.
	// taskkill handles the current descendant tree, without invoking a shell.
	// Bound the helper so unavailable taskkill cannot delay connection cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	kill := exec.CommandContext(ctx, "taskkill.exe", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F")
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = kill.Run()
	_ = cmd.Process.Kill()
}
