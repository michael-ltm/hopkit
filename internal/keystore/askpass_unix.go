//go:build darwin || linux

package keystore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// writeAskpass creates a fixed helper and a private FIFO. The passphrase is
// carried only in pipe memory, never a regular file, argument or environment
// variable. Cleanup cancels and joins the nonblocking writer before removing
// the directory. This is not isolation from other processes of the same user.
func writeAskpass(ctx context.Context, passphrase string) (string, func(), error) {
	// Keep the entire line within the portable minimum PIPE_BUF (512 bytes),
	// so one nonblocking write is atomic. Askpass itself is a one-line protocol.
	if len(passphrase) > 511 || strings.ContainsAny(passphrase, "\r\n\x00") {
		return "", nil, errors.New("passphrase cannot be delivered through askpass: requires one line of at most 511 bytes without NUL")
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "sshm-askpass-")
	if err != nil {
		return "", nil, errors.New("create private askpass directory failed")
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(dir)
		}
	}()
	fifo := filepath.Join(dir, "phrase")
	if err = unix.Mkfifo(fifo, 0600); err != nil {
		return "", nil, errors.New("create askpass pipe failed")
	}
	path := filepath.Join(dir, "askpass")
	const script = "#!/bin/sh\nunset phrase\nIFS= read -r phrase < \"${0%/*}/phrase\" || exit 1\nprintf '%s\\n' \"$phrase\"\n"
	if err = os.WriteFile(path, []byte(script), 0700); err != nil {
		return "", nil, errors.New("create askpass helper failed")
	}
	writerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var once sync.Once
	cleanup := func() { once.Do(func() { cancel(); <-done; _ = os.RemoveAll(dir) }) }
	data := []byte(passphrase + "\n")
	go func() {
		defer close(done)
		defer clear(data)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if writerCtx.Err() != nil {
				return
			}
			fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err == nil {
				// An empty FIFO has room for this single atomic write. Never switch to
				// blocking mode: cancellation and cleanup must always be bounded.
				_, _ = unix.Write(fd, data)
				_ = unix.Close(fd)
				return
			}
			if !errors.Is(err, unix.ENXIO) && !errors.Is(err, unix.EINTR) {
				return
			}
			select {
			case <-writerCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	failed = false
	return path, cleanup, nil
}

func runSSHAddWithAskpass(ctx context.Context, passphrase string, args ...string) error {
	askpass, cleanup, err := writeAskpass(ctx, passphrase)
	if err != nil {
		return fmt.Errorf("prepare askpass helper: %w", err)
	}
	defer cleanup()

	cmd := exec.CommandContext(ctx, "ssh-add", args...)
	// Kill the helper as well if ssh-add times out while it waits for input.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(),
		"SSH_ASKPASS="+askpass,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=", // some ssh-add builds require DISPLAY set for askpass
	)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("ssh-add timed out: %w", ctx.Err())
		}
		// Do not include subprocess output: a failing helper may echo secrets.
		return fmt.Errorf("ssh-add: %w", err)
	}
	return nil
}
