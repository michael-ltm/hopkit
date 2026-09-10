//go:build darwin

package keystore

import (
	"context"
	"fmt"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runSSHAddWithAskpass(ctx, passphrase, args...)
}
