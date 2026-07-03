# sshm — Secure-by-Default Key Provisioning

**Date**: 2026-07-03
**Author**: ming (michael-ltm)
**Status**: Draft — approved in brainstorm, awaiting spec review
**Target release**: v0.5.0

---

## 1. Problem

`gen_key` today writes an **unencrypted** private key to disk
(`internal/keys/generate.go` uses `gssh.MarshalPrivateKey` with no
passphrase). Every path that creates a key for a new server — the `add`
wizard, the `gen_key` MCP tool — therefore leaves a naked private key on
disk. If `~/.ssh` (or `%USERPROFILE%\.ssh`) leaks, those keys are
immediately usable by an attacker with zero effort.

v0.4.1 taught sshm to *consume* passphrase-encrypted keys (resolve the
matching identity from ssh-agent, cross-platform: unix socket / Windows
named pipe). The **creation** side was never hardened. This spec closes
that gap: keys sshm generates are encrypted by default, and the passphrase
is stored so the human/AI never has to retype it.

Non-goal restatement (from the v1 spec, still in force): no cloud key
escrow, no secrets vault, no session recording. This spec only hardens the
generate → install → register → harden onboarding flow.

## 2. Goals

When a server is added or provisioned through sshm — via the CLI wizard or
the MCP/AI surface — the default, no-extra-flags path is:

1. Key auth (not password).
2. The generated private key is **passphrase-encrypted** on disk.
3. The passphrase is stored in the OS keystore / agent so it is typed at
   most once (never, on macOS/Windows).
4. The user is offered server-side hardening (disable password auth) after
   the key is confirmed working.
5. Private-key material and passphrases **never** pass through the AI text
   channel.

Cross-platform: macOS, Windows, Linux.

## 3. Design

Two layers that back each other up.

### 3.1 Layer B — binary (the hard guarantee)

**(a) `gen_key` encrypts by default.**
`GenerateED25519` gains a passphrase parameter and uses
`gssh.MarshalPrivateKeyWithPassphrase`. A new signature, keeping the old
call sites compiling via a thin wrapper:

```
GenerateED25519Encrypted(keyPath, comment, passphrase string) (pubLine string, err error)
```

- Empty passphrase preserves today's unencrypted behavior (explicit opt-out
  only; callers must pass "" deliberately).
- The `.pub` file is written exactly as today (comment appended, 0644).
- The atomic-cleanup `defer os.Remove(keyPath)` on error is preserved.

**Passphrase model (decided): per-key random.**
sshm generates a strong random passphrase (diceware-style, ~4 words + digits,
generated from `crypto/rand`), stores it in the OS keystore, **and prints it
once** to the CLI so the user can save it to their password manager. Each key
gets its own passphrase → per-key blast radius. Rationale: a shared passphrase
means one cracked file endangers all; independent passphrases don't. The
one-time print is the recovery path if the keystore is ever lost.

**(b) New package `internal/keystore` — cross-platform passphrase/agent glue.**
One interface, three build-tagged implementations. This is where today's
hand-rolled shell knowledge becomes tool code.

```
package keystore
// StoreAndLoad encrypts-key passphrase into the OS keystore (where
// supported) and loads the key into the running agent so it is usable
// immediately and after reboot (where the platform persists it).
func StoreAndLoad(keyPath, passphrase string) (Result, error)
type Result struct {
    Persisted bool   // survives reboot/logout on this platform
    Note      string // human-readable caveat, e.g. Linux non-persistence
}
```

- **macOS** (`keystore_darwin.go`): `ssh-add --apple-use-keychain <key>`
  feeding the passphrase via a one-shot `SSH_ASKPASS` helper +
  `SSH_ASKPASS_REQUIRE=force` (no TTY prompt). Persisted = true. Gotchas
  encoded from today: add keys **one at a time**; over an SSH session (no
  GUI security context) storing silently fails — detect and return
  `Persisted:false` with a note instead of pretending success.
- **Windows** (`keystore_windows.go`): ensure the *OpenSSH Authentication
  Agent* service is `Automatic` + running, then `ssh-add <key>`. The agent
  DPAPI-persists the decrypted key, so passphrase isn't needed again.
  Persisted = true. (Reuses the pipe knowledge already in
  `agent_dial_windows.go`.)
- **Linux** (`keystore_linux.go`): `ssh-add <key>` into `$SSH_AUTH_SOCK`.
  Honest limitation: default ssh-agent does **not** persist across
  logout/reboot. Persisted = false, Note explains it; if `gnome-keyring` /
  `keychain` is detected, use it and set Persisted = true.

**(c) New orchestrator `provision`.**
CLI: `sshm provision <alias> --host … [--user …] [--port …] [--harden]`.
MCP tool: `provision` (write-class, requires `reason`, audited).
Steps, each idempotent and each failure surfaced:

1. `gen_key` (encrypted, per-key random passphrase) → `keystore.StoreAndLoad`.
2. `copy_id` — install the public key. **Password stays on the CLI**; the
   MCP tool returns the "run `sshm copy-id <alias>` in a terminal"
   instruction exactly as `copy_id` does today (password never through AI).
3. `add_server` with `auth = "key"`, `key_path` set.
4. `test_connection`.
5. If `--harden` (CLI) / `harden:true` (MCP) **and** step 4 passed: disable
   password auth server-side via the existing `bootstrap` path (drop-in
   `/etc/ssh/sshd_config.d/*.conf`, `sshd -t` before reload — never lock the
   user out on a bad config).

`provision` composes existing verbs; it does not reimplement them.

### 3.2 Layer A — SKILL.md (soft steering for the AI)

Add a "Secure server onboarding" section to
`plugins/sshm-skill/skills/sshm-server-ops/SKILL.md`:

- When the user asks to add/onboard a server, default to `provision` (or
  `gen_key` encrypted + `add_server auth=key` if provisioning piecemeal).
- Never choose password auth unless the user explicitly insists.
- After the key works, ask whether to disable password login server-side.
- Never emit private-key bytes or passphrases in chat; for `copy_id`, hand
  the user the CLI instruction.

## 4. Testing

- `keystore`: interface + a fake/injected runner so the sequencing and
  error-mapping are unit-tested without touching the real agent; the
  `StoreAndLoad` command construction asserted per-platform. Real-agent
  round-trip stays a manual/integration check (as with today's agent test
  that spins an in-memory keyring on a unix socket).
- `generate`: encrypted key round-trips — `ssh-keygen -y -P <pass>` (or
  `gssh.ParsePrivateKeyWithPassphrase`) recovers the same public key; empty
  passphrase still yields a parseable unencrypted key.
- `provision`: orchestration tested against fake step functions — asserts
  order, that a failed `test_connection` blocks harden, that `copy_id`
  defers to CLI, and that audit entries are written.
- Cross-compile gate: `GOOS=windows/linux/darwin go build ./...` all green
  (as enforced in v0.4.1).

## 5. Rollout (definition of done)

1. Implement per plan; `go test ./...` + three-OS cross-build green.
2. CHANGELOG + `.claude-plugin/marketplace.json` (2×) +
   `plugins/sshm-skill/.claude-plugin/plugin.json` bumped to 0.5.0.
3. Two-part commit (feat + docs), push `main`.
4. Tag `v0.5.0` → GoReleaser publishes GitHub release + updates
   homebrew-tap & scoop-bucket.
5. **Deploy + verify every machine**: local `brew upgrade sshm`; pc-e5
   (`~\bin`); mac mini (`~/.local/bin`); dps (`/usr/local/bin`). Each: run a
   real `provision`/`gen_key` and confirm the produced key is encrypted and
   loads from the keystore.

## 6. YAGNI (explicitly out of scope)

- Cloud/remote passphrase escrow or backup.
- Passphrase rotation UI (today's manual `ssh-keygen -p` suffices).
- Migrating existing on-disk unencrypted keys (a separate one-shot, not the
  onboarding path this spec covers).
- Non-ed25519 key types in the generate path.
