package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// appendMu serializes appends to the known_hosts file so concurrent dials of
// previously-unknown hosts don't interleave writes (TOFU pinning).
var appendMu sync.Mutex

// knownHostsPath returns the path to the user's known_hosts file, honoring
// $HOME via os.UserHomeDir.
func knownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

// ensureKnownHosts makes sure ~/.ssh exists (0700) and known_hosts exists
// (0600), creating them if absent. It is safe to call repeatedly.
func ensureKnownHosts(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return f.Close()
}

// tofuHostKeyCallback returns a HostKeyCallback implementing trust-on-first-use
// against the known_hosts file at path:
//   - host absent  → accept and append (pin), like StrictHostKeyChecking=accept-new
//   - host present and key matches → accept
//   - host present but key differs → reject (possible MITM)
func tofuHostKeyCallback(path string) gssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key gssh.PublicKey) error {
		if err := ensureKnownHosts(path); err != nil {
			return err
		}
		// Build the matcher fresh on each call so newly pinned hosts (and
		// hosts pinned by other processes) are picked up.
		matcher, err := knownhosts.New(path)
		if err != nil {
			return fmt.Errorf("read known_hosts %s: %w", path, err)
		}
		matchErr := matcher(hostname, remote, key)
		if matchErr == nil {
			return nil // known and matching
		}

		var keyErr *knownhosts.KeyError
		if errors.As(matchErr, &keyErr) {
			if len(keyErr.Want) == 0 {
				// Unknown host: pin it (TOFU accept-new).
				return appendKnownHost(path, hostname, remote, key)
			}
			// Host present but key differs: possible MITM.
			return fmt.Errorf(
				"host key mismatch for %s: possible MITM; remove the stale line from ~/.ssh/known_hosts if you trust the new key",
				hostname)
		}
		// Some other error (e.g. malformed file): surface it.
		return matchErr
	}
}

// appendKnownHost pins key for hostname by appending a properly-formatted line
// to the known_hosts file. Guarded by appendMu for concurrent dials.
func appendKnownHost(path, hostname string, remote net.Addr, key gssh.PublicKey) error {
	appendMu.Lock()
	defer appendMu.Unlock()

	// Re-check under the lock: another dial may have just pinned this host.
	if matcher, err := knownhosts.New(path); err == nil {
		if matcher(hostname, remote, key) == nil {
			return nil
		}
	}

	addrs := []string{knownhosts.Normalize(hostname)}
	if remote != nil {
		if ra := knownhosts.Normalize(remote.String()); ra != addrs[0] {
			addrs = append(addrs, ra)
		}
	}
	line := knownhosts.Line(addrs, key)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open known_hosts %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("append to known_hosts %s: %w", path, err)
	}
	return nil
}
