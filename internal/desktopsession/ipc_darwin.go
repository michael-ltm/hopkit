//go:build darwin

package desktopsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxRequestBytes = 1024 * 1024

func socketDir() string  { return fmt.Sprintf("/tmp/sshm-desktop-%d", os.Getuid()) }
func socketPath() string { return filepath.Join(socketDir(), "command.sock") }

func ownedPrivate(path string, dir bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != os.Getuid() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 || st.IsDir() != dir {
		return fmt.Errorf("desktop session path is not private and owned by this user: %s", path)
	}
	return nil
}

func prepareSocketDirectory() error {
	if err := os.Mkdir(socketDir(), 0700); err != nil && !os.IsExist(err) {
		return err
	}
	return ownedPrivate(socketDir(), true)
}

func sameUser(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var check error
	err = raw.Control(func(fd uintptr) {
		c, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			check = e
		} else if int(c.Uid) != os.Getuid() {
			check = errors.New("desktop session peer is a different OS user")
		}
	})
	if err != nil {
		return err
	}
	return check
}

func dial(ctx context.Context) (*net.UnixConn, error) {
	if err := ownedPrivate(socketDir(), true); err != nil {
		return nil, err
	}
	if err := ownedPrivate(socketPath(), false); err != nil {
		return nil, err
	}
	st, err := os.Lstat(socketPath())
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("desktop session endpoint is not a socket")
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "unix", socketPath())
	if err != nil {
		return nil, err
	}
	u := c.(*net.UnixConn)
	if err = sameUser(u); err != nil {
		u.Close()
		return nil, err
	}
	return u, nil
}

func inspectAt(ctx context.Context) (string, error) {
	conn, err := dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = json.NewEncoder(conn).Encode(request{Protocol: 1, Op: "ping"}); err != nil {
		return "", err
	}
	var f frame
	if err = json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&f); err != nil {
		return "", err
	}
	if f.Kind != "pong" {
		return "", errors.New("unexpected desktop session response")
	}
	return f.Version, nil
}

// Execute never retries a submitted command. Lost transport after submission is
// an unknown outcome, not permission to replay a potentially destructive action.
func Execute(ctx context.Context, command, directory string, stdout, stderr io.Writer) (int, error) {
	req := request{Protocol: 1, Op: "exec", Command: command, Directory: directory}
	payload, err := json.Marshal(req)
	if err != nil {
		return -1, err
	}
	if len(payload) > maxRequestBytes {
		return -1, errors.New("desktop command exceeds request limit")
	}
	conn, err := dial(ctx)
	if err != nil {
		return -1, fmt.Errorf("desktop session is enabled but unavailable; use sshm desktop status (command was not sent): %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write(append(payload, '\n')); err != nil {
		return -1, errors.New("desktop request delivery failed; outcome unknown, do not automatically retry")
	}
	dec := json.NewDecoder(conn)
	for {
		var f frame
		if err = dec.Decode(&f); err != nil {
			if ctx.Err() != nil {
				return -1, ctx.Err()
			}
			return -1, errors.New("desktop session disconnected before completion; outcome unknown, do not automatically retry")
		}
		switch f.Kind {
		case "stdout":
			if _, err = stdout.Write(f.Data); err != nil {
				return -1, err
			}
		case "stderr":
			if _, err = stderr.Write(f.Data); err != nil {
				return -1, err
			}
		case "exit":
			if f.Error != "" {
				return f.Code, errors.New(f.Error)
			}
			return f.Code, nil
		default:
			return -1, errors.New("invalid desktop session response")
		}
	}
}

type frameWriter struct {
	mu     *sync.Mutex
	enc    *json.Encoder
	kind   string
	cancel context.CancelFunc
}

func (w frameWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		end := len(p)
		if end > 16*1024 {
			end = 16 * 1024
		}
		w.mu.Lock()
		err := w.enc.Encode(frame{Kind: w.kind, Data: p[:end]})
		w.mu.Unlock()
		if err != nil {
			w.cancel()
			return n, err
		}
		n += end
		p = p[end:]
	}
	return n, nil
}

func serveConnection(parent context.Context, conn *net.UnixConn, version string) {
	defer conn.Close()
	if sameUser(conn) != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(io.LimitReader(conn, maxRequestBytes+1))
	var r request
	if err := dec.Decode(&r); err != nil || r.Protocol != 1 {
		return
	}
	enc := json.NewEncoder(conn)
	if r.Op == "ping" {
		_ = enc.Encode(frame{Kind: "pong", Version: version})
		return
	}
	if r.Op != "exec" || r.Command == "" || len(r.Command) > maxRequestBytes || !filepath.IsAbs(r.Directory) {
		_ = enc.Encode(frame{Kind: "exit", Code: 64, Error: "invalid desktop execution request"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// The client keeps its write side open. Any EOF or further request data
	// cancels this one command; pipelining/replay is intentionally unsupported.
	go func() { var b [1]byte; _, _ = dec.Buffered().Read(b[:]); _, _ = conn.Read(b[:]); cancel() }()
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}
	cmd := exec.CommandContext(ctx, shell, "-lc", r.Command)
	cmd.Dir = r.Directory
	cmd.Env = append(os.Environ(), "SSHM_EXECUTION_CONTEXT=desktop_user")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	var mu sync.Mutex
	cmd.Stdout = frameWriter{&mu, enc, "stdout", cancel}
	cmd.Stderr = frameWriter{&mu, enc, "stderr", cancel}
	err := cmd.Run()
	code := 0
	message := ""
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
			message = "desktop command could not complete: " + err.Error()
		}
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = enc.Encode(frame{Kind: "exit", Code: code, Error: message})
}

func Serve(ctx context.Context, version string) error {
	// Only launchd's Aqua session is allowed to start the broker. A manually
	// started SSH/background process must not masquerade as a desktop session.
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "managername").Output()
	if err != nil || strings.TrimSpace(string(out)) != "Aqua" {
		return errors.New("desktop service must run in the user's Aqua login session")
	}
	if err := prepareSocketDirectory(); err != nil {
		return err
	}
	if _, err := os.Lstat(socketPath()); err == nil {
		if _, alive := inspectAt(ctx); alive == nil {
			return errors.New("desktop session already running")
		}
		if err := ownedPrivate(socketPath(), false); err != nil {
			return err
		}
		st, _ := os.Lstat(socketPath())
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace a non-socket endpoint")
		}
		if err := os.Remove(socketPath()); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath(), Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socketPath(), 0600); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, 16)
	for {
		c, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-slots }(); serveConnection(ctx, c, version) }()
		default:
			_ = c.Close()
		}
	}
}
