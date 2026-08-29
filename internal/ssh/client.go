// Package ssh wraps golang.org/x/crypto/ssh with sshm-specific construction
// helpers and a small Client that owns one connection.
package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	gssh "golang.org/x/crypto/ssh"
)

// nopCloser is returned when no resource needs closing.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// BuildOpts is non-persistent input gathered at connect time (e.g. password
// prompted from TTY). Never write the contents of BuildOpts to disk.
type BuildOpts struct {
	Password string
	// Alias identifies a managed target for best-effort LastUsed tracking after
	// authentication succeeds. Empty leaves activity metadata untouched.
	Alias string
	// ActivityError receives a non-fatal error when authentication succeeded
	// but LastUsed/LastSeen could not be persisted. When nil, Dial writes a
	// concise warning to stderr so stale cleanup metadata is never silent.
	ActivityError func(error)
	// Insecure disables host-key verification (InsecureIgnoreHostKey). The
	// zero value is false: connections verify host keys via TOFU against
	// ~/.ssh/known_hosts by default.
	Insecure bool
	Timeout  time.Duration // 0 → default 10s
	// ConfigPath is the on-disk config path used to resolve a ProxyJump alias
	// to a known server. Empty falls back to config.ConfigPath(); if that
	// holds no matching alias the ProxyJump value is treated as a host spec.
	ConfigPath string
}

func reportActivityError(opts BuildOpts, err error) {
	if err == nil {
		return
	}
	if opts.ActivityError != nil {
		opts.ActivityError(err)
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "warning: SSH succeeded but activity history could not be saved: %v\n", err)
}

// BuildClientConfig produces a *ssh.ClientConfig from a Server entry.
// It also returns an io.Closer that the caller must close when done
// (releases the ssh-agent unix socket when agent auth is used).
func BuildClientConfig(s *config.Server, opts BuildOpts) (*gssh.ClientConfig, io.Closer, error) {
	if strings.TrimSpace(s.User) == "" {
		return nil, nil, errors.New("user is required")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	authMethods, closer, err := buildAuth(s, opts)
	if err != nil {
		return nil, nil, err
	}

	hostKey, err := hostKeyCallback(opts.Insecure)
	if err != nil {
		return nil, nil, err
	}

	if closer == nil {
		closer = nopCloser{}
	}
	return &gssh.ClientConfig{
		User:            s.User,
		Auth:            authMethods,
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	}, closer, nil
}

// Address joins host and port with default 22.
func Address(s *config.Server) string {
	port := s.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(s.Host, strconv.Itoa(port))
}

func buildAuth(s *config.Server, opts BuildOpts) ([]gssh.AuthMethod, io.Closer, error) {
	switch s.Auth {
	case config.AuthKey:
		key, closer, err := loadKeySigner(s.KeyPath)
		if err != nil {
			return nil, nil, err
		}
		return []gssh.AuthMethod{gssh.PublicKeys(key)}, closer, nil
	case config.AuthPassword:
		if opts.Password == "" {
			return nil, nil, errors.New("password not provided for auth=password (use --ask-password or keychain)")
		}
		return []gssh.AuthMethod{gssh.Password(opts.Password)}, nil, nil
	case config.AuthAgent:
		method, closer, err := agentAuth()
		if err != nil {
			return nil, nil, err
		}
		return []gssh.AuthMethod{method}, closer, nil
	default:
		return nil, nil, fmt.Errorf("unsupported auth %q (want one of key/password/agent)", s.Auth)
	}
}

// loadKeySigner returns a signer for the private key at path. Unencrypted
// keys are parsed directly (nil closer). Encrypted keys are resolved through
// the running ssh-agent by exact public-key match, so a keychain-backed agent
// supplies signatures without sshm ever handling the passphrase; the returned
// closer then owns the agent socket and must stay open while the signer is
// in use.
func loadKeySigner(path string) (gssh.Signer, io.Closer, error) {
	exp, err := ExpandHome(path)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(exp)
	if err != nil {
		return nil, nil, fmt.Errorf("read key %s: %w", exp, err)
	}
	signer, err := gssh.ParsePrivateKey(data)
	if err == nil {
		return signer, nil, nil
	}
	var missing *gssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, nil, fmt.Errorf("parse key %s: %w", exp, err)
	}
	pub := missing.PublicKey
	if pub == nil {
		// Legacy PEM encryption hides the public half; recover it from the
		// sibling .pub file when present.
		if pubData, perr := os.ReadFile(exp + ".pub"); perr == nil {
			if p, _, _, _, perr2 := gssh.ParseAuthorizedKey(pubData); perr2 == nil {
				pub = p
			}
		}
	}
	if pub == nil {
		return nil, nil, fmt.Errorf("key %s is encrypted and its public key is unknown; ssh-add it or create %s.pub: %w", exp, exp, err)
	}
	agentSigner, closer, aerr := agentSignerFor(pub)
	if aerr != nil {
		return nil, nil, fmt.Errorf("key %s is encrypted and unavailable via ssh-agent: %w", exp, aerr)
	}
	return agentSigner, closer, nil
}

// ExpandHome expands a leading ~ to the current user's home directory.
func ExpandHome(p string) (string, error) {
	if !strings.HasPrefix(p, "~") {
		return p, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand path %q: %w", p, err)
	}
	return filepath.Join(h, p[1:]), nil
}

// hostKeyCallback returns the HostKeyCallback to use for a connection. By
// default (insecure=false) it verifies host keys via trust-on-first-use
// against ~/.ssh/known_hosts: unknown hosts are pinned, matching hosts are
// accepted, and changed keys are rejected as a possible MITM. When insecure
// is true it returns InsecureIgnoreHostKey() as an explicit opt-out.
func hostKeyCallback(insecure bool) (gssh.HostKeyCallback, error) {
	if insecure {
		return gssh.InsecureIgnoreHostKey(), nil //nolint:gosec
	}
	path, err := knownHostsPath()
	if err != nil {
		return nil, err
	}
	return tofuHostKeyCallback(path), nil
}
