# Secure-by-Default Key Provisioning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every key sshm generates passphrase-encrypted by default, with the passphrase stored in the OS keystore and loadable cross-platform, plus a `provision` CLI that runs the full secure onboarding flow.

**Architecture:** A new `keys.GenerateED25519Encrypted` + `keys.RandomPassphrase` produce encrypted keys; a new `internal/keystore` package stores the passphrase / loads the key into the agent per-OS (reusing the agent-dial code v0.4.1 added in `internal/ssh`); `gen_key` (CLI + MCP) wires them together and writes a `0600` recovery file; a new `sshm provision` CLI composes gen-key → copy-id → auth=key → test → optional harden. SKILL.md steers the AI to the same defaults.

**Tech Stack:** Go 1.25, `golang.org/x/crypto/ssh` + `.../ssh/agent`, cobra CLI, mark3labs/mcp-go, testify.

## Global Constraints

- Go toolchain pinned at `1.25.x` (dependency floor from mcp-go; do not lower).
- Cross-build must stay green: `GOOS=darwin|linux|windows go build ./...`.
- Platform-specific files use build tags (`//go:build darwin` etc.), mirroring `internal/ssh/agent_dial_{unix,windows}.go`.
- Private-key bytes and passphrase values must never be returned through an MCP tool result (recovery-file *pointer* only); the CLI may print to the human TTY.
- Every MCP write-tool handler calls `requireReason(args)` first and `audit(deps, …)` on success (existing pattern).
- Conventional-commit messages; end each commit body with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Release = bump CHANGELOG + `.claude-plugin/marketplace.json` (2 occurrences) + `plugins/sshm-skill/.claude-plugin/plugin.json` to `0.5.0`, two-part commit (feat + docs), push `main`, tag `v0.5.0`.

---

### Task 1: `keys.RandomPassphrase` — high-entropy token generator

**Files:**
- Create: `internal/keys/passphrase.go`
- Test: `internal/keys/passphrase_test.go`

**Interfaces:**
- Produces: `func RandomPassphrase() (string, error)` — 32 random bytes rendered as URL-safe base64 without padding (43 chars, charset `[A-Za-z0-9_-]`). Sourced from `crypto/rand`.

- [ ] **Step 1: Write the failing test**

```go
package keys

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomPassphrase_ShapeAndCharset(t *testing.T) {
	p, err := RandomPassphrase()
	require.NoError(t, err)
	require.Len(t, p, 43) // 32 bytes base64url, no padding
	require.Regexp(t, regexp.MustCompile(`^[A-Za-z0-9_-]+$`), p)
}

func TestRandomPassphrase_Unique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		p, err := RandomPassphrase()
		require.NoError(t, err)
		require.False(t, seen[p], "passphrase repeated")
		seen[p] = true
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keys/ -run TestRandomPassphrase -v`
Expected: FAIL — `undefined: RandomPassphrase`.

- [ ] **Step 3: Write minimal implementation**

```go
// Package-level addition in internal/keys/passphrase.go
package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// RandomPassphrase returns a high-entropy passphrase (32 bytes of crypto/rand
// rendered as unpadded URL-safe base64). It is intended to be stored in an OS
// keystore, not memorised, so it favours entropy over readability.
func RandomPassphrase() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keys/ -run TestRandomPassphrase -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add internal/keys/passphrase.go internal/keys/passphrase_test.go
git commit -m "feat(keys): add RandomPassphrase high-entropy generator"
```

---

### Task 2: `keys.GenerateED25519Encrypted` + make `GenerateED25519` a wrapper

**Files:**
- Modify: `internal/keys/generate.go`
- Test: `internal/keys/generate_test.go` (add cases; keep existing green)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `func GenerateED25519Encrypted(keyPath, comment, passphrase string) (pubLine string, err error)` — same as `GenerateED25519` but, when `passphrase != ""`, encrypts the private key with `gssh.MarshalPrivateKeyWithPassphrase`. Empty passphrase → unencrypted (today's behaviour).
  - `func GenerateED25519(keyPath, comment string) (string, error)` — now delegates to `GenerateED25519Encrypted(keyPath, comment, "")`.

- [ ] **Step 1: Write the failing test**

```go
// add to internal/keys/generate_test.go
func TestGenerateED25519Encrypted_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_enc")
	pub, err := GenerateED25519Encrypted(path, "enc@host", "s3cr3t-pass")
	require.NoError(t, err)
	require.Contains(t, pub, "ssh-ed25519")

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	// Wrong/empty passphrase must fail; correct one must recover the key.
	_, err = gssh.ParseRawPrivateKey(data)
	require.Error(t, err, "encrypted key must not parse without a passphrase")

	signer, err := gssh.ParsePrivateKeyWithPassphrase(data, []byte("s3cr3t-pass"))
	require.NoError(t, err)
	require.Contains(t, string(gssh.MarshalAuthorizedKey(signer.PublicKey())), "ssh-ed25519")
}

func TestGenerateED25519Encrypted_EmptyPassphraseIsPlain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_plain")
	_, err := GenerateED25519Encrypted(path, "plain@host", "")
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = gssh.ParseRawPrivateKey(data) // parses without a passphrase
	require.NoError(t, err)
}
```

Add the import for `gssh "golang.org/x/crypto/ssh"` to the test file if not already present.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keys/ -run TestGenerateED25519Encrypted -v`
Expected: FAIL — `undefined: GenerateED25519Encrypted`.

- [ ] **Step 3: Write minimal implementation**

In `internal/keys/generate.go`, rename the existing body into the new function and add a wrapper. Replace the current `func GenerateED25519(...)` definition with:

```go
// GenerateED25519 writes a new unencrypted ed25519 keypair. See
// GenerateED25519Encrypted for the passphrase-protected form.
func GenerateED25519(keyPath, comment string) (pubLine string, err error) {
	return GenerateED25519Encrypted(keyPath, comment, "")
}

// GenerateED25519Encrypted writes a new ed25519 private key to keyPath
// (mode 0600) and its public key to keyPath+".pub" (mode 0644), returning the
// OpenSSH public-key line. When passphrase != "" the private key is encrypted
// with it. Refuses to overwrite an existing private key.
func GenerateED25519Encrypted(keyPath, comment, passphrase string) (pubLine string, err error) {
	comment = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, comment)

	if _, err = os.Stat(keyPath); err == nil {
		return "", fmt.Errorf("key already exists at %s (delete it first to regenerate)", keyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519: %w", err)
	}

	var pemBlock *pem.Block
	var mErr error
	if passphrase == "" {
		pemBlock, mErr = gssh.MarshalPrivateKey(priv, comment)
	} else {
		pemBlock, mErr = gssh.MarshalPrivateKeyWithPassphrase(priv, comment, []byte(passphrase))
	}
	if mErr != nil {
		return "", fmt.Errorf("marshal private key: %w", mErr)
	}
	if err = os.WriteFile(keyPath, encodePEM(pemBlock), 0o600); err != nil {
		return "", fmt.Errorf("write private key %s: %w", keyPath, err)
	}
	defer func() {
		if err != nil {
			os.Remove(keyPath)
		}
	}()

	sshPub, err2 := gssh.NewPublicKey(pub)
	if err2 != nil {
		err = fmt.Errorf("marshal public key: %w", err2)
		return "", err
	}
	pubLine = string(gssh.MarshalAuthorizedKey(sshPub))
	pubLine = pubLine[:len(pubLine)-1] + " " + comment + "\n"
	if err = os.WriteFile(keyPath+".pub", []byte(pubLine), 0o644); err != nil {
		err = fmt.Errorf("write public key %s: %w", keyPath+".pub", err)
		return "", err
	}
	return pubLine, nil
}
```

Add `"encoding/pem"` to the import block if `MarshalPrivateKey`'s return type reference requires it (it returns `*pem.Block`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/keys/ -v`
Expected: PASS — new cases plus all three existing `TestGenerateED25519_*` still green (the wrapper preserves behaviour).

- [ ] **Step 5: Commit**

```bash
git add internal/keys/generate.go internal/keys/generate_test.go
git commit -m "feat(keys): GenerateED25519Encrypted with passphrase support"
```

---

### Task 3: Export `ssh.DialAgent` for reuse by the keystore

**Files:**
- Create: `internal/ssh/agent_dial.go`
- Test: covered indirectly by existing agent tests; no new test (thin exported wrapper over already-tested `dialAgent`).

**Interfaces:**
- Consumes: existing unexported `dialAgent() (net.Conn, error)` (per-OS, in `agent_dial_unix.go` / `agent_dial_windows.go`).
- Produces: `func DialAgent() (net.Conn, error)` — exported wrapper so packages outside `internal/ssh` can reach the running agent using the same per-OS logic.

- [ ] **Step 1: Write the wrapper (no new behaviour to TDD — it forwards)**

```go
package ssh

import "net"

// DialAgent connects to the running ssh-agent using the platform-appropriate
// transport (unix socket via SSH_AUTH_SOCK, or the Windows OpenSSH agent
// named pipe). Callers own the returned connection and must Close it.
func DialAgent() (net.Conn, error) { return dialAgent() }
```

- [ ] **Step 2: Verify build on all three OSes**

Run:
```bash
go build ./... && GOOS=windows go build ./... && GOOS=linux go build ./...
```
Expected: all exit 0.

- [ ] **Step 3: Commit**

```bash
git add internal/ssh/agent_dial.go
git commit -m "refactor(ssh): export DialAgent for keystore reuse"
```

---

### Task 4: `internal/keystore` — shared surface + agent-load helper

**Files:**
- Create: `internal/keystore/keystore.go` (shared types + `agentAdd` helper used by the unix/linux and windows loaders)
- Test: `internal/keystore/keystore_test.go`

**Interfaces:**
- Consumes: `keys.GenerateED25519Encrypted` output (an encrypted key on disk); `ssh.DialAgent`.
- Produces:
  - `type Result struct { Persisted bool; Note string }`
  - `func StoreAndLoad(keyPath, passphrase string) (Result, error)` — the public entry point (real body is per-OS in Tasks 5–6; this file declares `Result` and the shared `agentAdd`).
  - `func agentAdd(keyPath, passphrase string) error` — parse the encrypted key with the passphrase and add the decrypted identity to the running agent via the agent protocol. Used by the linux and windows loaders.

- [ ] **Step 1: Write the failing test** (in-memory agent over a unix socket, mirroring `internal/ssh/keysigner_test.go`)

```go
//go:build !windows

package keystore

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAgentAdd_LoadsDecryptedIdentity(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pass123")
	require.NoError(t, err)

	kr := agent.NewKeyring()
	// os.MkdirTemp (not t.TempDir) keeps the socket path under macOS's
	// 104-byte sun_path limit.
	sdir, err := os.MkdirTemp("", "ks-agent")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(sdir) })
	sock := filepath.Join(sdir, "a.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)

	require.NoError(t, agentAdd(keyPath, "pass123"))

	keysInAgent, err := kr.List()
	require.NoError(t, err)
	require.Len(t, keysInAgent, 1)

	want, err := gssh.ParsePrivateKeyWithPassphrase(mustRead(t, keyPath), []byte("pass123"))
	require.NoError(t, err)
	require.Equal(t, want.PublicKey().Marshal(), keysInAgent[0].Blob)
}

func TestAgentAdd_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "right")
	require.NoError(t, err)
	require.Error(t, agentAdd(keyPath, "wrong"))
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keystore/ -run TestAgentAdd -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Write minimal implementation**

```go
package keystore

import (
	"fmt"
	"os"

	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Result describes what StoreAndLoad achieved on this platform.
type Result struct {
	Persisted bool   // survives reboot/logout without re-entering the passphrase
	Note      string // human-readable caveat (may be empty)
}

// agentAdd parses the encrypted key at keyPath with passphrase and adds the
// decrypted identity to the running ssh-agent. It does not persist the
// passphrase; persistence is a per-OS concern handled by StoreAndLoad.
func agentAdd(keyPath, passphrase string) error {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key %s: %w", keyPath, err)
	}
	raw, err := gssh.ParseRawPrivateKeyWithPassphrase(data, []byte(passphrase))
	if err != nil {
		return fmt.Errorf("decrypt key %s: %w", keyPath, err)
	}
	conn, err := sshpkg.DialAgent()
	if err != nil {
		return fmt.Errorf("dial agent: %w", err)
	}
	defer conn.Close()
	if err := agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: raw}); err != nil {
		return fmt.Errorf("add key to agent: %w", err)
	}
	return nil
}
```

Note: `StoreAndLoad` itself is defined per-OS in Tasks 5 and 6, so it is **not** in this file. This file must compile on all OSes on its own (it only defines `Result` and `agentAdd`).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keystore/ -run TestAgentAdd -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/keystore/keystore.go internal/keystore/keystore_test.go
git commit -m "feat(keystore): shared Result type and agent-load helper"
```

---

### Task 5: keystore `StoreAndLoad` for Linux and Windows (agent-based)

**Files:**
- Create: `internal/keystore/store_linux.go` (`//go:build linux`)
- Create: `internal/keystore/store_windows.go` (`//go:build windows`)
- Test: `internal/keystore/store_agent_test.go` (`//go:build linux || windows`)

**Interfaces:**
- Consumes: `agentAdd` (Task 4).
- Produces: `func StoreAndLoad(keyPath, passphrase string) (Result, error)` on linux and windows.

- [ ] **Step 1: Write the failing test**

```go
//go:build linux || windows

package keystore

// Reuses the in-memory agent harness style; on these platforms StoreAndLoad
// loads via the agent. On Windows the OS agent persists; here we only assert
// the key is loaded and no error is returned.
import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestStoreAndLoad_AgentPlatforms(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pw")
	require.NoError(t, err)

	kr := agent.NewKeyring()
	sdir, err := os.MkdirTemp("", "ks-agent")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(sdir) })
	sock := filepath.Join(sdir, "a.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)

	res, err := StoreAndLoad(keyPath, "pw")
	require.NoError(t, err)
	loaded, err := kr.List()
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	_ = res // Persisted/Note are platform-dependent; not asserted here
}
```

(Note: the Windows OpenSSH agent uses a named pipe, not `SSH_AUTH_SOCK`; this test exercises the linux path in CI's linux runner and is compiled-but-representative on windows. `DialAgent` on windows ignores a unix `SSH_AUTH_SOCK`, so on the windows runner this test is skipped by the guard below.)

Add at the top of the test function:
```go
	if runtimeIsWindows() {
		t.Skip("windows agent uses a named pipe, not a unix socket")
	}
```
and a helper in the same file:
```go
func runtimeIsWindows() bool { return os.PathSeparator == '\\' }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keystore/ -run TestStoreAndLoad_AgentPlatforms -v`
Expected: FAIL — `undefined: StoreAndLoad` (on linux/darwin dev host the linux file isn't built; run with `GOOS` unset on Linux, or rely on CI. On a macOS dev host, verify via `GOOS=linux go vet ./internal/keystore/` after Step 3 instead.)

- [ ] **Step 3: Write minimal implementation**

`internal/keystore/store_linux.go`:
```go
//go:build linux

package keystore

// StoreAndLoad loads the decrypted key into the running ssh-agent. The default
// Linux ssh-agent does not persist identities across logout/reboot, so
// Persisted is false and the note explains it.
func StoreAndLoad(keyPath, passphrase string) (Result, error) {
	if err := agentAdd(keyPath, passphrase); err != nil {
		return Result{}, err
	}
	return Result{
		Persisted: false,
		Note:      "loaded into ssh-agent for this session; Linux ssh-agent does not persist across reboot — re-run `sshm` after login, or use a keyring agent (gnome-keyring/keychain) for persistence",
	}, nil
}
```

`internal/keystore/store_windows.go`:
```go
//go:build windows

package keystore

// StoreAndLoad loads the decrypted key into the Windows OpenSSH agent, which
// persists added identities across reboots (DPAPI). Persisted is true.
func StoreAndLoad(keyPath, passphrase string) (Result, error) {
	if err := agentAdd(keyPath, passphrase); err != nil {
		return Result{}, err
	}
	return Result{Persisted: true}, nil
}
```

- [ ] **Step 4: Verify**

Run:
```bash
GOOS=linux go vet ./internal/keystore/
GOOS=windows go vet ./internal/keystore/
```
Expected: both exit 0. On a Linux host, `go test ./internal/keystore/ -run TestStoreAndLoad_AgentPlatforms -v` should PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/keystore/store_linux.go internal/keystore/store_windows.go internal/keystore/store_agent_test.go
git commit -m "feat(keystore): StoreAndLoad for linux and windows"
```

---

### Task 6: keystore `StoreAndLoad` for macOS (keychain via ssh-add)

**Files:**
- Create: `internal/keystore/store_darwin.go` (`//go:build darwin`)
- Test: `internal/keystore/store_darwin_test.go` (`//go:build darwin`)

**Interfaces:**
- Produces: `func StoreAndLoad(keyPath, passphrase string) (Result, error)` on darwin, storing the passphrase in the login keychain via `ssh-add --apple-use-keychain` (persistent) and falling back to `agentAdd` (session-only) when the keychain is unavailable (e.g. running over SSH with no security context).
- Internal seam for testing: `var runSSHAdd = defaultRunSSHAdd` so tests can assert the command/args without spawning `ssh-add`.

- [ ] **Step 1: Write the failing test** (asserts command construction + fallback via the injected seam)

```go
//go:build darwin

package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/stretchr/testify/require"
)

func TestStoreAndLoad_Darwin_UsesAppleKeychain(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pw")
	require.NoError(t, err)

	var gotArgs []string
	var gotPass string
	orig := runSSHAdd
	t.Cleanup(func() { runSSHAdd = orig })
	runSSHAdd = func(passphrase string, args ...string) error {
		gotArgs = args
		gotPass = passphrase
		return nil
	}

	res, err := StoreAndLoad(keyPath, "pw")
	require.NoError(t, err)
	require.True(t, res.Persisted)
	require.Contains(t, gotArgs, "--apple-use-keychain")
	require.Contains(t, gotArgs, keyPath)
	require.Equal(t, "pw", gotPass)
}

func TestStoreAndLoad_Darwin_FallsBackToSessionAgent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_enc")
	_, err := keys.GenerateED25519Encrypted(keyPath, "k@test", "pw")
	require.NoError(t, err)

	orig := runSSHAdd
	t.Cleanup(func() { runSSHAdd = orig })
	runSSHAdd = func(passphrase string, args ...string) error {
		return errors.New("keychain unavailable: no security session")
	}
	// No agent socket set → agentAdd also fails, but StoreAndLoad must
	// surface a non-persistent Result path, not panic. Point at a dead socket.
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "nope.sock"))

	res, err := StoreAndLoad(keyPath, "pw")
	// Either an error (agent unreachable) or a non-persistent result is
	// acceptable; what matters is Persisted is not falsely true.
	if err == nil {
		require.False(t, res.Persisted)
		require.NotEmpty(t, res.Note)
	}
	_ = os.Getpid
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keystore/ -run TestStoreAndLoad_Darwin -v`
Expected: FAIL — `undefined: StoreAndLoad` / `runSSHAdd`.

- [ ] **Step 3: Write minimal implementation**

```go
//go:build darwin

package keystore

import (
	"fmt"
	"os"
	"os/exec"
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
		return err
	}
	defer os.Remove(askpass)

	cmd := exec.Command("ssh-add", args...)
	cmd.Env = append(os.Environ(),
		"SSH_ASKPASS="+askpass,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=", // some ssh-add builds require DISPLAY set for askpass
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-add: %v: %s", err, out)
	}
	return nil
}

// writeAskpass writes a temporary executable that prints the passphrase, for
// use via SSH_ASKPASS. Mode 0700, removed by the caller.
func writeAskpass(passphrase string) (string, error) {
	f, err := os.CreateTemp("", "sshm-askpass-*.sh")
	if err != nil {
		return "", err
	}
	// Single-quote the passphrase and escape embedded single quotes.
	script := "#!/bin/sh\nprintf '%s\\n' '" +
		escapeSingleQuotes(passphrase) + "'\n"
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if err := os.Chmod(f.Name(), 0o700); err != nil {
		os.Remove(f.Name())
		return "", err
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
```

(The base64url passphrase from Task 1 never contains a single quote, but `escapeSingleQuotes` keeps the helper safe for any caller-supplied passphrase.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/keystore/ -run TestStoreAndLoad_Darwin -v`
Expected: PASS (both cases). Then `go test ./internal/keystore/ -v` for the whole package.

- [ ] **Step 5: Commit**

```bash
git add internal/keystore/store_darwin.go internal/keystore/store_darwin_test.go
git commit -m "feat(keystore): StoreAndLoad macOS keychain path with agent fallback"
```

---

### Task 7: Recovery-file writer + wire the encrypting flow into the `gen-key` CLI

**Files:**
- Create: `internal/keys/recovery.go`
- Modify: `internal/commands/genkey.go`
- Test: `internal/keys/recovery_test.go`, `internal/commands/genkey_test.go` (extend)

**Interfaces:**
- Produces: `func WriteRecovery(keyPath, passphrase string) (recoveryPath string, err error)` — writes `keyPath+".passphrase"` mode `0600` containing the passphrase + a one-line header, refusing to overwrite. Returns the path.
- CLI change: `sshm gen-key <alias>` now generates a random passphrase, encrypts the key, stores it via `keystore.StoreAndLoad`, writes the recovery file, and prints the passphrase + recovery path + persistence note to the human terminal. A `--no-encrypt` flag preserves the old plaintext behaviour for escape hatches.

- [ ] **Step 1: Write the failing test for WriteRecovery**

```go
package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteRecovery_WritesModeAndContent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_x")
	rp, err := WriteRecovery(keyPath, "topsecret")
	require.NoError(t, err)
	require.Equal(t, keyPath+".passphrase", rp)

	data, err := os.ReadFile(rp)
	require.NoError(t, err)
	require.Contains(t, string(data), "topsecret")

	if os.PathSeparator == '/' {
		st, err := os.Stat(rp)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}
	require.True(t, strings.Contains(string(data), "id_x"), "header names the key")
}

func TestWriteRecovery_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_x")
	_, err := WriteRecovery(keyPath, "a")
	require.NoError(t, err)
	_, err = WriteRecovery(keyPath, "b")
	require.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keys/ -run TestWriteRecovery -v`
Expected: FAIL — `undefined: WriteRecovery`.

- [ ] **Step 3: Implement WriteRecovery**

```go
package keys

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteRecovery writes the key's passphrase to keyPath+".passphrase" (mode
// 0600), refusing to overwrite. This is the one-time recovery copy the user
// should move into a password manager and then delete.
func WriteRecovery(keyPath, passphrase string) (string, error) {
	rp := keyPath + ".passphrase"
	if _, err := os.Stat(rp); err == nil {
		return "", fmt.Errorf("recovery file already exists at %s", rp)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	body := fmt.Sprintf("# sshm recovery — passphrase for %s\n# move this into your password manager, then delete this file\n%s\n",
		filepath.Base(keyPath), passphrase)
	if err := os.WriteFile(rp, []byte(body), 0o600); err != nil {
		return "", fmt.Errorf("write recovery %s: %w", rp, err)
	}
	return rp, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keys/ -run TestWriteRecovery -v`
Expected: PASS.

- [ ] **Step 5: Update the gen-key CLI**

In `internal/commands/genkey.go`, replace the `RunE` body's key-generation section. Add a `--no-encrypt` flag and the encrypting path:

```go
func newGenKeyCmd() *cobra.Command {
	var path string
	var noEncrypt bool
	c := &cobra.Command{
		Use:   "gen-key <alias>",
		Short: "Generate an encrypted ed25519 keypair for an alias and update its key_path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			s, err := resolveServer(cfg, args[0])
			if err != nil {
				return err
			}
			actualPath := path
			if actualPath == "" {
				actualPath = filepath.Join("~", ".ssh", "id_ed25519_"+args[0])
			}
			expanded, err := sshpkg.ExpandHome(actualPath)
			if err != nil {
				return err
			}

			var passphrase string
			if !noEncrypt {
				passphrase, err = keys.RandomPassphrase()
				if err != nil {
					return err
				}
			}
			pub, err := keys.GenerateED25519Encrypted(expanded, args[0]+"@sshm", passphrase)
			if err != nil {
				return err
			}

			s.KeyPath = actualPath
			if err := saveConfig(cfg); err != nil {
				return err
			}

			var recoveryPath string
			var store keystore.Result
			if passphrase != "" {
				store, err = keystore.StoreAndLoad(expanded, passphrase)
				if err != nil {
					return fmt.Errorf("key generated at %s but keystore step failed: %w", expanded, err)
				}
				recoveryPath, err = keys.WriteRecovery(expanded, passphrase)
				if err != nil {
					return err
				}
			}

			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"alias":         args[0],
					"key_path":      expanded,
					"public_key":    strings.TrimSpace(pub),
					"encrypted":     passphrase != "",
					"persisted":     store.Persisted,
					"recovery_file": recoveryPath,
				})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, expanded)
			fmt.Fprintln(out, pub)
			if passphrase != "" {
				fmt.Fprintf(out, "\nPassphrase (save to your password manager): %s\n", passphrase)
				fmt.Fprintf(out, "Recovery file (delete after saving): %s\n", recoveryPath)
				if store.Persisted {
					fmt.Fprintln(out, "Stored in keychain — you won't be prompted again.")
				} else if store.Note != "" {
					fmt.Fprintf(out, "Note: %s\n", store.Note)
				}
			}
			return nil
		},
	}
	c.Flags().StringVarP(&path, "path", "p", "", "key path (default ~/.ssh/id_ed25519_<alias>)")
	c.Flags().BoolVar(&noEncrypt, "no-encrypt", false, "generate an unencrypted key (not recommended)")
	return c
}
```

Add imports: `"github.com/michael-ltm/sshm/internal/keystore"`.

- [ ] **Step 6: Extend the gen-key CLI test**

The existing `genkey_test.go` calls gen-key and checks output. Encrypting now loads into the agent, which the test environment may lack. Add `--no-encrypt` to the existing invocation so the current assertions hold, and add one new test asserting the default path reports `encrypted:true` in JSON. Because `StoreAndLoad` needs a reachable agent, gate the encrypting CLI test behind an available `SSH_AUTH_SOCK`:

```go
func TestGenKeyCmd_DefaultIsEncrypted(t *testing.T) {
	// Opt-in only: the real keystore step runs `ssh-add --apple-use-keychain`,
	// which would pollute the developer's real login keychain. Routine
	// `go test ./...` and CI skip this; run with SSHM_KEYSTORE_E2E=1 manually.
	if os.Getenv("SSHM_KEYSTORE_E2E") == "" {
		t.Skip("set SSHM_KEYSTORE_E2E=1 to exercise the real keystore path")
	}
	// ... set up temp config with one alias (mirror the existing test's
	// harness), run `gen-key <alias> --json`, decode, and:
	//   require.Equal(t, true, result["encrypted"])
}
```

For the existing test that must keep passing without an agent, change its args to include `--no-encrypt`.

- [ ] **Step 7: Run tests**

Run: `go test ./internal/keys/ ./internal/commands/ -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/keys/recovery.go internal/keys/recovery_test.go internal/commands/genkey.go internal/commands/genkey_test.go
git commit -m "feat(cli): gen-key encrypts by default, stores passphrase, writes recovery"
```

---

### Task 8: Encrypting `gen_key` MCP tool (recovery pointer, no passphrase in result)

**Files:**
- Modify: `internal/mcp/tools_ops.go` (`handleGenKey`)
- Test: `internal/mcp/tools_ops_test.go` if present, else add `internal/mcp/genkey_test.go`

**Interfaces:**
- Consumes: `keys.RandomPassphrase`, `keys.GenerateED25519Encrypted`, `keystore.StoreAndLoad`, `keys.WriteRecovery`.
- Produces: `gen_key` MCP result now includes `encrypted`, `persisted`, `recovery_file` (a path) and **never** the passphrase value.

- [ ] **Step 1: Write the failing test**

```go
func TestHandleGenKey_EncryptsAndHidesPassphrase(t *testing.T) {
	// Opt-in only (real keystore side effects). See Task 7 note.
	if os.Getenv("SSHM_KEYSTORE_E2E") == "" {
		t.Skip("set SSHM_KEYSTORE_E2E=1 to exercise the real keystore path")
	}
	// Build Deps with a temp config containing one alias (mirror existing
	// MCP handler tests). Call handleGenKey with a temp key path + reason.
	res, err := handleGenKey(context.Background(), deps, map[string]any{
		"alias": "srv", "path": keyPath, "reason": "test",
	})
	require.NoError(t, err)
	m := res.(map[string]any)
	require.Equal(t, true, m["encrypted"])
	require.NotContains(t, m, "passphrase")            // never returned
	require.Contains(t, m["recovery_file"].(string), ".passphrase")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcp/ -run TestHandleGenKey_EncryptsAndHidesPassphrase -v`
Expected: FAIL (result lacks `encrypted`).

- [ ] **Step 3: Update handleGenKey**

Replace the generation + result section of `handleGenKey`:

```go
	passphrase, err := keys.RandomPassphrase()
	if err != nil {
		return errResult("keygen", err.Error()), nil
	}
	pub, err := keys.GenerateED25519Encrypted(expanded, alias+"@sshm", passphrase)
	if err != nil {
		return errResult("keygen", err.Error()), nil
	}
	store, err := keystore.StoreAndLoad(expanded, passphrase)
	if err != nil {
		return errResult("keystore", err.Error()), nil
	}
	recoveryPath, err := keys.WriteRecovery(expanded, passphrase)
	if err != nil {
		return errResult("recovery", err.Error()), nil
	}

	if uerr := config.Update(deps.ConfigPath, func(cfg *config.Config) error {
		if s, ok := cfg.Servers[alias]; ok {
			s.KeyPath = path
			s.Auth = config.AuthKey
		}
		return nil
	}); uerr != nil {
		return errResult("config", uerr.Error()), nil
	}
	audit(deps, safety.Entry{Tool: "gen_key", Alias: alias, Reason: reason, Result: "ok"})
	return map[string]any{
		"alias":         alias,
		"key_path":      expanded,
		"public_key":    strings.TrimSpace(pub),
		"encrypted":     true,
		"persisted":     store.Persisted,
		"recovery_file": recoveryPath,
		"note":          store.Note,
	}, nil
```

Add imports `"github.com/michael-ltm/sshm/internal/keystore"` (and keep `keys`).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcp/ -run TestHandleGenKey -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/mcp/tools_ops.go internal/mcp/*genkey*_test.go
git commit -m "feat(mcp): gen_key encrypts, returns recovery pointer not passphrase"
```

---

### Task 9: `sshm provision` CLI orchestrator

**Files:**
- Create: `internal/commands/provision.go`
- Modify: `internal/commands/root.go` (register the command)
- Test: `internal/commands/provision_test.go`

**Interfaces:**
- Consumes: `keys.RandomPassphrase`, `keys.GenerateED25519Encrypted`, `keystore.StoreAndLoad`, `keys.WriteRecovery`, `keys.CopyID`, existing `resolveServer`/`loadConfig`/`saveConfig`, and the harden path used by `bootstrap` (reuse whatever `internal/commands` already calls for hardening; if none, shell the drop-in via an existing exec helper).
- Produces: `sshm provision <alias> [--path P] [--harden]`. Orchestration is factored so the test can inject step functions:
  - `type provisionSteps struct { genKey func() (string, error); copyID func(password string) error; test func() error; harden func() error }`
  - `func runProvision(steps provisionSteps, doHarden bool, keyConfirmed *bool) error` — the pure orchestration, unit-tested; the cobra `RunE` builds real steps and calls it.

- [ ] **Step 1: Write the failing test for orchestration order + harden gating**

```go
package commands

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunProvision_HardenSkippedWhenTestFails(t *testing.T) {
	var order []string
	steps := provisionSteps{
		genKey: func() (string, error) { order = append(order, "gen"); return "pub", nil },
		copyID: func(pw string) error { order = append(order, "copy"); return nil },
		test:   func() error { order = append(order, "test"); return errors.New("unreachable") },
		harden: func() error { order = append(order, "harden"); return nil },
	}
	err := runProvision(steps, true /*doHarden*/, nil)
	require.Error(t, err)
	require.Equal(t, []string{"gen", "copy", "test"}, order, "harden must not run after a failed test")
}

func TestRunProvision_FullOrderWhenHealthy(t *testing.T) {
	var order []string
	steps := provisionSteps{
		genKey: func() (string, error) { order = append(order, "gen"); return "pub", nil },
		copyID: func(pw string) error { order = append(order, "copy"); return nil },
		test:   func() error { order = append(order, "test"); return nil },
		harden: func() error { order = append(order, "harden"); return nil },
	}
	require.NoError(t, runProvision(steps, true, nil))
	require.Equal(t, []string{"gen", "copy", "test", "harden"}, order)
}

func TestRunProvision_NoHardenFlag(t *testing.T) {
	var order []string
	steps := provisionSteps{
		genKey: func() (string, error) { order = append(order, "gen"); return "pub", nil },
		copyID: func(pw string) error { order = append(order, "copy"); return nil },
		test:   func() error { order = append(order, "test"); return nil },
		harden: func() error { order = append(order, "harden"); return nil },
	}
	require.NoError(t, runProvision(steps, false, nil))
	require.Equal(t, []string{"gen", "copy", "test"}, order)
}
```

(`copyID` takes the password because the real step reads it from the TTY before calling `runProvision`; in tests it is ignored. The `keyConfirmed *bool` param lets the real RunE learn whether harden ran; pass `nil` when unused.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/commands/ -run TestRunProvision -v`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement orchestration + command**

`internal/commands/provision.go`:
```go
package commands

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/keystore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type provisionSteps struct {
	genKey func() (string, error)
	copyID func(password string) error
	test   func() error
	harden func() error
}

// runProvision executes the onboarding steps in order and refuses to harden
// unless the connectivity test passed. password prompting happens in RunE.
func runProvision(steps provisionSteps, doHarden bool, keyConfirmed *bool) error {
	if _, err := steps.genKey(); err != nil {
		return fmt.Errorf("gen-key: %w", err)
	}
	if err := steps.copyID(""); err != nil {
		return fmt.Errorf("copy-id: %w", err)
	}
	if err := steps.test(); err != nil {
		return fmt.Errorf("connectivity test: %w", err)
	}
	if keyConfirmed != nil {
		*keyConfirmed = true
	}
	if doHarden {
		if err := steps.harden(); err != nil {
			return fmt.Errorf("harden: %w", err)
		}
	}
	return nil
}

func newProvisionCmd() *cobra.Command {
	var path string
	var doHarden bool
	c := &cobra.Command{
		Use:   "provision <alias>",
		Short: "Securely onboard an existing alias: encrypted key, install, test, optional harden",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			s, err := resolveServer(cfg, args[0])
			if err != nil {
				return err
			}
			actualPath := path
			if actualPath == "" {
				actualPath = filepath.Join("~", ".ssh", "id_ed25519_"+args[0])
			}
			expanded, err := sshpkg.ExpandHome(actualPath)
			if err != nil {
				return err
			}

			// Read the server password once, up front (needed by copy-id).
			fmt.Fprintf(cmd.ErrOrStderr(), "Password for %s@%s: ", s.User, s.Host)
			pw, err := term.ReadPassword(0)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer func() {
				for i := range pw {
					pw[i] = 0
				}
			}()

			steps := provisionSteps{
				genKey: func() (string, error) {
					passphrase, gerr := keys.RandomPassphrase()
					if gerr != nil {
						return "", gerr
					}
					pub, gerr := keys.GenerateED25519Encrypted(expanded, args[0]+"@sshm", passphrase)
					if gerr != nil {
						return "", gerr
					}
					s.KeyPath = actualPath
					s.Auth = config.AuthKey
					if serr := saveConfig(cfg); serr != nil {
						return "", serr
					}
					store, serr := keystore.StoreAndLoad(expanded, passphrase)
					if serr != nil {
						return "", serr
					}
					rp, serr := keys.WriteRecovery(expanded, passphrase)
					if serr != nil {
						return "", serr
					}
					fmt.Fprintf(cmd.OutOrStdout(), "Passphrase (save to your password manager): %s\nRecovery file: %s\n", passphrase, rp)
					if !store.Persisted && store.Note != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "Note: %s\n", store.Note)
					}
					return pub, nil
				},
				copyID: func(string) error {
					return keys.CopyID(context.Background(), s, string(pw), expanded)
				},
				test: func() error {
					cli, terr := sshpkg.Dial(s, sshpkg.BuildOpts{})
					if terr != nil {
						return terr
					}
					return cli.Close()
				},
				harden: func() error {
					return hardenDisablePassword(context.Background(), s)
				},
			}
			if err := runProvision(steps, doHarden, nil); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "provisioned: key auth working"+hardenedSuffix(doHarden))
			return nil
		},
	}
	c.Flags().StringVarP(&path, "path", "p", "", "key path (default ~/.ssh/id_ed25519_<alias>)")
	c.Flags().BoolVar(&doHarden, "harden", false, "after key auth works, disable password login on the server")
	return c
}

func hardenedSuffix(h bool) string {
	if h {
		return "; password login disabled"
	}
	return ""
}
```

For `hardenDisablePassword`, reuse the existing bootstrap/harden logic. Check `internal/commands/*.go` and `internal/keys`/`internal/ssh` for an existing helper (the MCP `bootstrap` path). If a reusable function exists, call it. If not, implement a minimal one in `provision.go`:

```go
// hardenDisablePassword installs a drop-in that disables password auth, after
// validating with `sshd -t` so a bad config can never lock the user out.
func hardenDisablePassword(ctx context.Context, s *config.Server) error {
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return err
	}
	defer cli.Close()
	cmd := `set -e; f=/etc/ssh/sshd_config.d/99-sshm-key-only.conf; ` +
		`printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > "$f"; ` +
		`sshd -t && (systemctl reload sshd 2>/dev/null || systemctl reload ssh || service ssh reload)`
	res, err := cli.Exec(ctx, cmd)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("harden exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}
```

- [ ] **Step 4: Register the command**

In `internal/commands/root.go`, the `root.AddCommand(...)` block (around line 28) lists constructors one per line. Add `newProvisionCmd(),` right after `newGenKeyCmd(),`.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/commands/ -run TestRunProvision -v`
Expected: PASS (all three). Then `go build ./...`.

- [ ] **Step 6: Commit**

```bash
git add internal/commands/provision.go internal/commands/root.go internal/commands/provision_test.go
git commit -m "feat(cli): add provision — encrypted key onboarding with optional harden"
```

---

### Task 10: SKILL.md secure-onboarding guidance (Layer A)

**Files:**
- Modify: `plugins/sshm-skill/skills/sshm-server-ops/SKILL.md`
- Modify: `plugins/sshm-skill/skills/sshm-server-ops/quick-reference.md`

**Interfaces:** none (documentation steering the AI).

- [ ] **Step 1: Add a "Secure server onboarding" section to SKILL.md**

Insert after the tool list (near the `gen_key`/`copy_id` bullets):

```markdown
## Secure server onboarding (default)

When the user asks to add or onboard a server, default to key authentication —
never password auth unless they explicitly insist:

1. `add_server` with `auth=key` (this is already the default when a key is
   involved).
2. `gen_key` — this now generates a **passphrase-encrypted** key, stores the
   passphrase in the OS keystore, and writes a `0600` recovery file. The tool
   result gives you `recovery_file` (a path) but **never** the passphrase
   itself — do not ask for or echo passphrases or private-key contents.
3. Tell the user to run `sshm copy-id <alias>` (or `sshm provision <alias>`)
   in a terminal to install the key — copy-id needs the server password, which
   must stay on the CLI and never pass through you.
4. After key auth works, offer to disable password login on the server
   (`sshm provision <alias> --harden`, or the bootstrap path). Recommend it for
   internet-facing servers; ask first — the user may have others who log in
   with passwords.

Never place private-key bytes, passphrases, or recovery-file contents in chat.
```

- [ ] **Step 2: Add the provision line to quick-reference.md**

Add under the commands list:
```markdown
- `sshm provision <alias> [--harden]` — encrypted key + install + test (+ optionally disable password login). The secure default for onboarding.
```

- [ ] **Step 3: Commit**

```bash
git add plugins/sshm-skill/skills/sshm-server-ops/SKILL.md plugins/sshm-skill/skills/sshm-server-ops/quick-reference.md
git commit -m "docs(skill): secure server onboarding guidance"
```

---

### Task 11: Full verification + three-OS cross-build

**Files:** none (verification only).

- [ ] **Step 1: Format + vet + test**

Run:
```bash
cd ~/Documents/code/project/my/sshm
gofmt -l . && go vet ./... && go test ./...
```
Expected: `gofmt -l` prints nothing; vet clean; all packages `ok`.

- [ ] **Step 2: Cross-build all targets**

Run:
```bash
go build ./... && GOOS=windows go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./...
```
Expected: all exit 0.

- [ ] **Step 3: Manual smoke on the dev Mac (real agent + keychain)**

Run against a throwaway alias (do NOT harden a real server here):
```bash
go run ./cmd/sshm add smoketest --host 127.0.0.1 --user nobody --auth key || true
go run ./cmd/sshm gen-key smoketest --path /tmp/sshm-smoke/id_test
```
Expected: prints a key path, a passphrase, a recovery-file path, and "Stored in keychain". Confirm the key is encrypted:
```bash
ssh-keygen -y -P '' -f /tmp/sshm-smoke/id_test 2>&1 | grep -qi 'incorrect passphrase\|load failed' && echo "ENCRYPTED (good)"
test -f /tmp/sshm-smoke/id_test.passphrase && echo "recovery file present"
```
Then clean up (also drop the throwaway identity from the real agent/keychain):
```bash
ssh-add -d /tmp/sshm-smoke/id_test 2>/dev/null || true
rm -rf /tmp/sshm-smoke
go run ./cmd/sshm rm smoketest
```

- [ ] **Step 4: Commit any formatting fixes**

```bash
git add -A && git commit -m "chore: gofmt" || echo "nothing to format"
```

---

### Task 12: Release v0.5.0 + deploy to all machines

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `.claude-plugin/marketplace.json` (2 version occurrences)
- Modify: `plugins/sshm-skill/.claude-plugin/plugin.json` (1 version)

- [ ] **Step 1: Update CHANGELOG.md**

Add under `## [Unreleased]` a new section:
```markdown
## [0.5.0] — 2026-07-03

### Added
- Secure-by-default key provisioning. `gen_key` (CLI and MCP) now generates a **passphrase-encrypted** ed25519 key, stores the passphrase in the OS keystore (macOS login keychain via `ssh-add --apple-use-keychain`; Windows OpenSSH agent / DPAPI; Linux ssh-agent, session-only), and writes a `0600` recovery file. The MCP result returns only a recovery-file pointer — never the passphrase.
- `sshm provision <alias> [--harden]` — one command to generate an encrypted key, install it (one-shot password on the CLI), verify key auth, and optionally disable password login on the server.
- `internal/keystore` package: cross-platform passphrase storage + agent loading, reusing the v0.4.1 per-OS agent dialer.

### Changed
- `sshm gen-key` encrypts by default; pass `--no-encrypt` for the old plaintext behaviour.
```

- [ ] **Step 2: Bump versions**

```bash
cd ~/Documents/code/project/my/sshm
sed -i '' 's/"version": "0.4.1"/"version": "0.5.0"/g' .claude-plugin/marketplace.json plugins/sshm-skill/.claude-plugin/plugin.json
grep -n '"version"' .claude-plugin/marketplace.json plugins/sshm-skill/.claude-plugin/plugin.json
```
Expected: three lines now read `0.5.0`.

- [ ] **Step 3: Commit docs + push**

```bash
git add CHANGELOG.md .claude-plugin/marketplace.json plugins/sshm-skill/.claude-plugin/plugin.json
git commit -m "docs: v0.5.0 changelog, plugin bump"
git push origin main
```

- [ ] **Step 4: Tag + watch release**

```bash
git tag -a v0.5.0 -m "v0.5.0: secure-by-default key provisioning"
git push origin v0.5.0
gh run watch "$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')" --exit-status
```
Expected: GoReleaser run succeeds; `gh release view v0.5.0` shows assets; homebrew-tap + scoop-bucket updated.

- [ ] **Step 5: Deploy to every machine + verify**

```bash
# local
brew update && brew upgrade sshm && sshm version   # expect 0.5.0

# dps (Linux amd64) — download+install fresh binary
# mac mini (darwin arm64) — replace ~/.local/bin/sshm
# pc-e5 (windows amd64) — replace ~\bin\sshm.exe (kill running sshm first)
```
For each remote, download the matching v0.5.0 asset, install over the old binary, and run `sshm version` (expect `0.5.0`). Then verify the feature on at least the Mac mini and pc-e5 with a throwaway alias: `sshm gen-key <throwaway> --path <tmp>` produces an encrypted key + recovery file and reports keystore persistence. Remove the throwaway alias and temp keys afterward.

- [ ] **Step 6: Final commit (if any deploy notes/scripts were added to the repo)**

No repo changes expected in this step; deployment is operational. Update the memory files (`project_sshm.md`, `project_ssh_keys_encrypted.md`) with v0.5.0 status.

---

## Self-Review Notes

- **Spec coverage:** gen_key-encrypts (Tasks 2,7,8) ✓; per-key random passphrase (Task 1) ✓; keystore mac/win/linux (Tasks 4,5,6) ✓; recovery file + never-through-AI (Tasks 7,8) ✓; provision + harden gating (Task 9) ✓; SKILL.md (Task 10) ✓; MCP `provision` explicitly deferred per spec §6 ✓; rollout/deploy/push (Task 12) ✓.
- **Cross-platform:** build-tagged files mirror `agent_dial_{unix,windows}.go`; three-OS build gate in Task 11.
- **Never-through-AI:** MCP result asserts `NotContains "passphrase"` (Task 8); CLI-only password for copy-id (Task 9).
