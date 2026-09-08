//go:build darwin

package desktopsession

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func nativeGHPath() (string, error) {
	d, e := markerDir()
	if e != nil {
		return "", e
	}
	p := filepath.Join(d, "gh-path")
	if e = ownedPrivate(p, false); e != nil {
		return "", e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	name := strings.TrimSpace(string(b))
	if !filepath.IsAbs(name) {
		return "", errors.New("invalid native gh path")
	}
	return name, nil
}

// installGitHubShim saves executable paths only, never credential material.
// Only gh and Git's GitHub credential helper use the GUI broker. Git itself and
// all filesystem work remain in the original SSH/TCC execution context.
func installGitHubShim(executable string) error {
	d, e := markerDir()
	if e != nil {
		return e
	}
	dir := filepath.Join(d, "bin")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if e = ownedPrivate(dir, true); e != nil {
		return e
	}
	p := filepath.Join(d, "gh-path")
	if _, e = os.Lstat(p); os.IsNotExist(e) {
		gh, e := exec.LookPath("gh")
		if e != nil {
			for _, candidate := range []string{"/opt/homebrew/bin/gh", "/usr/local/bin/gh"} {
				if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
					gh = candidate
					e = nil
					break
				}
			}
		}
		if e != nil {
			return fmt.Errorf("gh was not found in this session PATH or common installation paths: %w", e)
		}
		gh, e = filepath.Abs(gh)
		if e != nil {
			return e
		}
		if strings.HasPrefix(gh, dir+string(os.PathSeparator)) {
			return errors.New("cannot resolve native gh outside the SSHM shim")
		}
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.WriteString(gh + "\n")
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	} else if e != nil {
		return e
	} else if e = ownedPrivate(p, false); e != nil {
		return e
	}
	shim := filepath.Join(dir, "gh")
	if _, e = os.Lstat(shim); e == nil {
		if e = ownedPrivate(shim, false); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	f, e := os.CreateTemp(dir, ".gh-")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	_, e = f.WriteString("#!/bin/sh\nexec " + quote(executable) + " desktop gh -- \"$@\"\n")
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Chmod(temp, 0700); e != nil {
		return e
	}
	return os.Rename(temp, shim)
}

type credentialBuffer struct{ bytes.Buffer }

func (b *credentialBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64*1024 {
		return 0, errors.New("credential response too large")
	}
	return b.Buffer.Write(p)
}

func githubCredential(ctx context.Context) ([]byte, error) {
	gh, e := nativeGHPath()
	if e != nil {
		return nil, e
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, e
	}
	var b credentialBuffer
	defer func() { clear(b.Bytes()); b.Reset() }()
	command := "'" + strings.ReplaceAll(gh, "'", "'\"'\"'") + "' auth token --hostname github.com"
	code, e := Execute(ctx, command, home, &b, io.Discard)
	if e != nil || code != 0 {
		return nil, errors.New("existing GitHub credential is unavailable in the desktop session; check desktop/keychain access, not a new login")
	}
	value := bytes.TrimSpace(b.Bytes())
	if len(value) == 0 || bytes.ContainsAny(value, "\r\n\x00") {
		return nil, errors.New("invalid desktop credential response")
	}
	return bytes.Clone(value), nil
}

var readDesktopGitHubCredential = githubCredential

func RunGitHub(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	gh, e := nativeGHPath()
	if e != nil {
		return -1, e
	}
	if len(args) > 1 && args[0] == "auth" {
		switch args[1] {
		case "login", "logout", "refresh", "switch":
			return -1, errors.New("change GitHub logins in your desktop terminal with the native gh; this bridge only reuses existing authorization")
		}
	}
	env := os.Environ()
	// Explicit caller credentials and enterprise selection retain precedence.
	useDesktop := os.Getenv("GH_TOKEN") == "" && os.Getenv("GITHUB_TOKEN") == "" && (os.Getenv("GH_HOST") == "" || os.Getenv("GH_HOST") == "github.com") && os.Getenv("GH_CONFIG_DIR") == "" && os.Getenv("XDG_CONFIG_HOME") == ""
	for _, arg := range args {
		if arg == "--help" || arg == "-h" || arg == "--version" {
			useDesktop = false
		}
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "version") {
		useDesktop = false
	}
	if len(args) > 1 && args[0] == "auth" && args[1] == "setup-git" {
		useDesktop = false
	}
	if len(args) > 1 && args[0] == "auth" && args[1] == "git-credential" {
		// Bind the delegated credential to HTTPS github.com only. Unsupported hosts
		// and store/erase operations return no credential rather than leaking one.
		if len(args) < 3 || args[2] != "get" {
			return 0, nil
		}
		data, e := io.ReadAll(io.LimitReader(stdin, 64*1024+1))
		if e != nil {
			return -1, e
		}
		if len(data) > 64*1024 {
			return -1, errors.New("credential request too large")
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
			if ok {
				fields[k] = v
			}
		}
		if fields["protocol"] != "https" || fields["host"] != "github.com" {
			return 0, nil
		}
		stdin = bytes.NewReader(data)
	}
	var value []byte
	if useDesktop {
		value, e = readDesktopGitHubCredential(ctx)
		if e != nil {
			return -1, e
		}
		defer clear(value)
		env = append(env, "GH_TOKEN="+string(value))
	}
	// Run the real CLI under the caller's SSH/file-access context. The delegated
	// value exists only in this short-lived child environment, not command args,
	// files, logs, a shared shell environment, or MCP tool results.
	cmd := exec.CommandContext(ctx, gh, args...)
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if e = cmd.Run(); e != nil {
		var ee *exec.ExitError
		if errors.As(e, &ee) {
			return ee.ExitCode(), nil
		}
		return -1, e
	}
	return 0, nil
}
