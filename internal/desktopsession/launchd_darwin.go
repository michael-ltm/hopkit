//go:build darwin

package desktopsession

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const label = "net.yunmini.sshm.desktop"

func markerDir() (string, error) {
	h, e := os.UserHomeDir()
	return filepath.Join(h, "Library", "Application Support", "sshm", "desktop"), e
}
func markerPath() (string, error) { d, e := markerDir(); return filepath.Join(d, "enabled"), e }
func agentPath() (string, error) {
	h, e := os.UserHomeDir()
	return filepath.Join(h, "Library", "LaunchAgents", label+".plist"), e
}
func domain() string { return "gui/" + strconv.Itoa(os.Getuid()) }
func escaped(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func Inspect(ctx context.Context) Status {
	s := Status{Supported: true}
	if p, e := markerPath(); e == nil {
		s.Enabled = ownedPrivate(p, false) == nil
	}
	if v, e := inspectAt(ctx); e == nil {
		s.Running = true
		s.Version = v
	}
	return s
}

func Enable(ctx context.Context, executable string) (Status, error) {
	if !filepath.IsAbs(executable) {
		return Status{}, errors.New("desktop service requires an absolute SSHM executable path")
	}
	// Validate the actual owning user's GUI domain; never substitute another
	// desktop user, sudo, or copy credentials out of a different security session.
	if e := exec.CommandContext(ctx, "/bin/launchctl", "print", domain()).Run(); e != nil {
		return Status{}, errors.New("this OS user has no accessible desktop login session; log into macOS first")
	}
	d, e := markerDir()
	if e != nil {
		return Status{}, e
	}
	if e = os.MkdirAll(d, 0700); e != nil {
		return Status{}, e
	}
	if e = ownedPrivate(d, true); e != nil {
		return Status{}, e
	}
	p, e := agentPath()
	if e != nil {
		return Status{}, e
	}
	if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return Status{}, e
	}
	if _, e = os.Lstat(p); e == nil {
		if e = ownedPrivate(p, false); e != nil {
			return Status{}, e
		}
		// Do not overwrite an existing job definition or interrupt active commands.
		old, e := os.ReadFile(p)
		if e != nil {
			return Status{}, e
		}
		if !bytes.Contains(old, []byte("<string>"+escaped(executable)+"</string>")) {
			return Status{}, errors.New("desktop agent uses another executable; disable it explicitly before changing its path")
		}
	} else if os.IsNotExist(e) {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/zsh"
		}
		home, e := os.UserHomeDir()
		if e != nil {
			return Status{}, e
		}
		payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>desktop</string><string>serve</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>%s</string><key>SHELL</key><string>%s</string><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
`, label, escaped(executable), escaped(home), escaped(shell))
		f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return Status{}, e
		}
		_, e = f.WriteString(payload)
		closeErr := f.Close()
		if e != nil {
			return Status{}, e
		}
		if closeErr != nil {
			return Status{}, closeErr
		}
	} else {
		return Status{}, e
	}
	if !Inspect(ctx).Running {
		load := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", domain(), p)
		if e = load.Run(); e != nil {
			// kickstart without -k will not kill an already-running service.
			if e = exec.CommandContext(ctx, "/bin/launchctl", "kickstart", domain()+"/"+label).Run(); e != nil {
				return Status{}, errors.New("cannot start desktop agent in the owning user's GUI session")
			}
		}
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if Inspect(ctx).Running {
			break
		}
		select {
		case <-ctx.Done():
			return Status{}, ctx.Err()
		case <-deadline.C:
			return Status{}, errors.New("desktop agent did not become ready; routing remains unchanged")
		case <-ticker.C:
		}
	}
	if e = installGitHubShim(executable); e != nil {
		return Status{}, e
	}
	marker, _ := markerPath()
	if _, e = os.Lstat(marker); e == nil {
		if e = ownedPrivate(marker, false); e != nil {
			return Status{}, e
		}
	} else if os.IsNotExist(e) {
		f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return Status{}, e
		}
		_, e = f.WriteString("1\n")
		closeErr := f.Close()
		if e != nil {
			return Status{}, e
		}
		if closeErr != nil {
			return Status{}, closeErr
		}
	} else {
		return Status{}, e
	}
	return Inspect(ctx), nil
}

func Disable(ctx context.Context) error {
	p, e := markerPath()
	if e != nil {
		return e
	}
	if _, e = os.Lstat(p); e == nil {
		if e = ownedPrivate(p, false); e != nil {
			return e
		}
		if e = os.Remove(p); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	// Explicit disable stops the service and its active child commands.
	if e = exec.CommandContext(ctx, "/bin/launchctl", "bootout", domain()+"/"+label).Run(); e != nil {
		if exec.CommandContext(ctx, "/bin/launchctl", "print", domain()+"/"+label).Run() == nil {
			return errors.New("desktop service is still loaded")
		}
	}
	p, e = agentPath()
	if e != nil {
		return e
	}
	if _, e = os.Lstat(p); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if e = ownedPrivate(p, false); e != nil {
		return e
	}
	return os.Remove(p)
}
