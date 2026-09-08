package ssh

import (
	"bytes"
	"context"
	"errors"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	"io"
	"strings"
	"time"
)

type platformOutput struct{ bytes.Buffer }

func (w *platformOutput) Write(p []byte) (int, error) {
	n := len(p)
	if w.Len() < 4096 {
		w.Buffer.Write(p[:min(n, 4096-w.Len())])
	}
	return n, nil
}
func PlatformFromOutput(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(s, "microsoft windows"), strings.HasPrefix(s, "mingw"), strings.HasPrefix(s, "cygwin"):
		return config.PlatformWindows
	case s == "darwin":
		return config.PlatformMacOS
	case s == "linux":
		return config.PlatformLinux
	}
	return ""
}

// DetectPlatform reads an authenticated target's OS; it never uses the hostname
// or SSH banner to guess and never records a probe as a user connection.
func (c *Client) DetectPlatform(ctx context.Context) string {
	for _, command := range []string{"uname -s", "cmd /c ver"} {
		out, e := c.platformCommand(ctx, command)
		if e == nil {
			if p := PlatformFromOutput(out); p != "" {
				return p
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return ""
}
func RecordPlatform(path, alias string, expected *config.Server, platform string) error {
	if platform == "" || alias == "" {
		return nil
	}
	return config.Update(path, func(cfg *config.Config) error {
		server := cfg.Servers[alias]
		if server != nil && server.Host == expected.Host && server.Port == expected.Port && server.User == expected.User {
			server.Platform = platform
		}
		return nil
	})
}
func (c *Client) detectManagedPlatform(s *config.Server, opts BuildOpts, path string) {
	if opts.Alias == "" || (s.Platform != "" && time.Since(s.SSHMCheckedAt) < 24*time.Hour) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	platform := s.Platform
	if platform == "" {
		platform = c.DetectPlatform(ctx)
		if platform != "" {
			_ = RecordPlatform(path, opts.Alias, s, platform)
		}
	}
	status, version := c.DetectSSHM(ctx, platform)
	_ = RecordSSHM(path, opts.Alias, s, status, version, time.Now())
}

// Session creation may block before SSH honors a command context. Keep metadata
// discovery bounded without closing the user's main SSH connection.
func (c *Client) platformCommand(ctx context.Context, command string) (string, error) {
	return c.observationCommand(ctx, command, false)
}
func (c *Client) observationCommand(ctx context.Context, command string, hardware bool) (string, error) {
	if c.conn == nil {
		return "", errors.New("SSH client not connected")
	}
	type result struct {
		output string
		err    error
	}
	done := make(chan result, 1)
	conn := c.conn
	go func() {
		session, err := conn.NewSession()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer session.Close()
		if ctx.Err() != nil {
			done <- result{err: ctx.Err()}
			return
		}
		var small platformOutput
		var large inventory.Output
		var out interface {
			io.Writer
			String() string
		} = &small
		if hardware {
			out = &large
		}
		session.Stdout = out
		session.Stderr = io.Discard
		finished := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = session.Close()
			case <-finished:
			}
		}()
		err = session.Run(command)
		close(finished)
		done <- result{out.String(), err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-done:
		return r.output, r.err
	}
}
