//go:build windows

package keystore

import (
	"context"
	"errors"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"os/exec"
	"time"
)

func EnsureAgent() error {
	if c, e := sshpkg.DialAgent(); e == nil {
		c.Close()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';Set-Service ssh-agent -StartupType Automatic;Start-Service ssh-agent").Run(); err != nil {
		return errors.New("Windows SSH agent is unavailable; start the ssh-agent service as administrator")
	}
	c, err := sshpkg.DialAgent()
	if err != nil {
		return err
	}
	return c.Close()
}
