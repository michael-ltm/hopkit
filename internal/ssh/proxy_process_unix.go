//go:build !windows

package ssh

import (
	"os/exec"
	"syscall"
)

// A private process group prevents cancellation from signaling sshm or other
// processes while retaining the shell's ordinary quoting and command behavior.
func prepareProxyProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateProxyProcess(cmd *exec.Cmd) {
	// The shell and all descendants that inherited its process group must stop;
	// killing only the shell leaves proxy children holding pipes and connections.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
