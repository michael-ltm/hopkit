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

// StartSessionAgent reuses a reachable agent or starts the Windows OpenSSH
// agent service. Windows has no in-process fallback (the unix serveGoAgent
// path serves a unix socket that does not apply to the OpenSSH named pipe).
func StartSessionAgent(_ context.Context) error {
	if c, e := sshpkg.DialAgent(); e == nil {
		c.Close()
		return nil
	}
	return EnsureAgent()
}
