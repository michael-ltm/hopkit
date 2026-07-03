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
sshm generates a strong per-key passphrase — a high-entropy token from
`crypto/rand` (32 bytes, base64url; the passphrase is machine-stored and never
typed, so memorability has no value and a wordlist would only weaken it). It is
stored in the OS keystore. Each key gets its own passphrase → per-key blast
radius; a shared passphrase means one cracked file endangers all, independent
ones don't.

**Recovery + the "never through AI" rule.** The passphrase must reach the user
(to save in a password manager) as a fallback if the keystore is ever lost —
but it must never pass through the AI text channel. Mechanism:

- On generation, write the passphrase once to a `0600` recovery file at
  `<keyPath>.passphrase`.
- The **CLI** additionally echoes it to the human terminal and tells the user
  to move it to their password manager and delete the file.
- The **MCP/AI** result returns only a *pointer* — "passphrase stored in
  keystore; recovery copy at `<path>` (move to your password manager, then
  delete)" — never the passphrase value.

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

**(c) New CLI orchestrator `sshm provision`.**
`sshm provision <alias> [--path …] [--harden]` (the alias must already exist
with host/user/port; add it first with `sshm add` or `add_server`). Because
`copy-id` needs the server password, full end-to-end provisioning is a **CLI**
command (it can prompt for the password on the TTY); the password never leaves
the terminal. Steps, each surfaced on failure:

1. `gen_key` (encrypted, per-key random passphrase) → `keystore.StoreAndLoad`
   → recovery file.
2. `copy_id` — prompt for the server password on the TTY, install the public
   key (one-shot password, never persisted).
3. Set the alias to `auth = "key"`, `key_path`.
4. `test_connection`.
5. If `--harden` **and** step 4 passed: disable password auth server-side via
   the existing `bootstrap` path (drop-in `/etc/ssh/sshd_config.d/*.conf`,
   `sshd -t` before reload — never lock the user out on a bad config).

`provision` composes existing verbs; it does not reimplement them.

**MCP/AI path — no new tool.** The AI does not need a `provision` MCP tool: the
security default is already carried by (i) `gen_key` now encrypting +
storing + recovery-pointer, and (ii) `add_server` already defaulting to
`auth=key`. The AI composes `add_server` → `gen_key` and then hands the user
the CLI instruction for `copy-id`/`provision` (password stays off the AI
channel, exactly as `copy_id` does today). Sequencing lives in SKILL.md
(Layer A). A dedicated MCP `provision` tool is deferred (YAGNI) — see §6.

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
- `provision`: orchestration tested against injected step functions —
  asserts step order and that a failed `test_connection` blocks the harden
  step (never touch sshd if the key isn't confirmed working).
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

- A dedicated MCP `provision` tool (the AI path is already secured by an
  encrypting `gen_key` + `add_server` + SKILL.md sequencing; a bespoke tool
  only saves round-trips and would need the password off-channel anyway).
- Cloud/remote passphrase escrow or backup.
- Passphrase rotation UI (today's manual `ssh-keygen -p` suffices).
- Migrating existing on-disk unencrypted keys (a separate one-shot, not the
  onboarding path this spec covers).
- Non-ed25519 key types in the generate path.
