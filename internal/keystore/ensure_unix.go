//go:build !windows

package keystore

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// StartSessionAgent reuses a reachable agent, or serves a process-local agent
// on the managed socket until ctx is cancelled. It does not persist keys.
func StartSessionAgent(ctx context.Context) error {
	if c, e := sshpkg.DialAgent(); e == nil {
		c.Close()
		return nil
	}
	if err := EnsureAgent(); err == nil {
		return nil
	}
	return serveGoAgent(ctx)
}

func serveGoAgent(ctx context.Context) error {
	if ctx == nil {
		return errors.New("missing agent context")
	}
	path := sshpkg.ManagedAgentPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("managed agent directory must be private and not a symlink")
	}
	if _, err := os.Lstat(path); err == nil {
		if c, e := sshpkg.DialAgent(); e == nil {
			c.Close()
			return nil
		}
		if e := os.Remove(path); e != nil {
			return e
		}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return err
	}
	ring := agent.NewKeyring()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(ring, c) }()
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, e := sshpkg.DialAgent()
		if e == nil {
			c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = listener.Close()
	_ = os.Remove(path)
	return errors.New("managed session agent did not become reachable")
}
