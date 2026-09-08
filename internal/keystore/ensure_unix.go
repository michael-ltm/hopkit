//go:build !windows

package keystore

import (
	"context"
	"errors"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// EnsureAgent starts an explicitly requested user-owned agent only when no
// existing agent can be reached. No passphrase or key is persisted here.
func EnsureAgent() error {
	if c, e := sshpkg.DialAgent(); e == nil {
		c.Close()
		return nil
	}
	if os.Getenv("SSH_AUTH_SOCK") != "" {
		return errors.New("configured SSH_AUTH_SOCK is unavailable; reconnect the intended agent before migrating keys")
	}
	path := sshpkg.ManagedAgentPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("managed agent directory must be private and not a symlink")
	}
	// Never unlink a socket from another concurrent invocation.
	if _, err := os.Lstat(path); err == nil {
		return errors.New("managed agent socket exists but is unavailable; inspect it before restarting")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "ssh-agent", "-a", path, "-s").Run(); err != nil {
		return errors.New("cannot start a user SSH agent")
	}
	c, err := sshpkg.DialAgent()
	if err != nil {
		return err
	}
	return c.Close()
}
