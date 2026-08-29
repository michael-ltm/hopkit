//go:build darwin

package keystore

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// runSSHAdd runs `ssh-add <args...>`, feeding passphrase through a one-shot
// SSH_ASKPASS helper so no TTY prompt appears. Swappable in tests.
var runSSHAdd = defaultRunSSHAdd

// StoreAndLoad stores the key passphrase in the macOS login keychain (so it is
// never typed again) and loads the key into the agent. If the keychain is
// unavailable (e.g. over an SSH session with no security context), it falls
// back to loading the key into the agent for this session only.
func StoreAndLoad(keyPath, passphrase string) (Result, error) {
	if err := runSSHAdd(passphrase, "--apple-use-keychain", keyPath); err == nil {
		return Result{Persisted: true}, nil
	}
	// Fallback: session-only load via the agent protocol.
	if err := agentAdd(keyPath, passphrase); err != nil {
		return Result{}, fmt.Errorf("keychain store failed and agent load failed: %w", err)
	}
	return Result{
		Persisted: false,
		Note:      "could not store in login keychain (no GUI security context?); loaded into agent for this session only",
	}, nil
}

func defaultRunSSHAdd(passphrase string, args ...string) error {
	askpass, err := writeAskpass(passphrase)
	if err != nil {
		return fmt.Errorf("write askpass helper: %w", err)
	}
	defer os.Remove(askpass)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-add", args...)
	cmd.Env = append(os.Environ(),
		"SSH_ASKPASS="+askpass,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=", // some ssh-add builds require DISPLAY set for askpass
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("ssh-add timed out: %w", ctx.Err())
		}
		return fmt.Errorf("ssh-add: %w: %s", err, out)
	}
	return nil
}

// writeAskpass writes a temporary executable that prints the passphrase, for
// use via SSH_ASKPASS. Mode 0700, removed by the caller.
func writeAskpass(passphrase string) (string, error) {
	f, err := os.CreateTemp("", "sshm-askpass-*.sh")
	if err != nil {
		return "", fmt.Errorf("create askpass temp file: %w", err)
	}
	// Single-quote the passphrase and escape embedded single quotes.
	script := "#!/bin/sh\nprintf '%s\\n' '" +
		escapeSingleQuotes(passphrase) + "'\n"
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write askpass script: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("close askpass script: %w", err)
	}
	if err := os.Chmod(f.Name(), 0o700); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("chmod askpass script: %w", err)
	}
	return f.Name(), nil
}

func escapeSingleQuotes(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\'' {
			out = append(out, '\'', '\\', '\'', '\'')
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
