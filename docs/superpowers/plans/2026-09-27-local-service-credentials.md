# Local service and persistent credentials implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Trusted local SSH works across AI processes and restarts without repeated cloud unlock, while stored credentials remain encrypted.

**Architecture:** A device-protected local credential store is the source of usable SSH credentials; local service lifecycle and cloud synchronization are independent. Stable target identity is separate from route selection. CLI and MCP share the same resolver, with a managed service for background restoration/sync and compatibility Agent access.

**Tech Stack:** Go, x/crypto SSH/AES-GCM, existing config file locks, platform credential protection and service managers.

**Spec:** `docs/superpowers/specs/2026-09-27-local-service-credentials-design.md` (approved by user).

**Status:** implementation and independent review complete; final delivery verification is recorded in `../reports/2026-09-27-local-service-credentials.md`. Checked tasks include the explicitly recorded platform/runtime limits below.

## Global constraints

- Preserve unrelated edits in the original checkout; implement in `/tmp/sshm-local-service-20260927` and copy only this change back after verification.
- Never log or return private keys, passphrases, passwords, tokens or device wrapping keys through MCP.
- No plaintext key or passphrase sidecars. Device protection material is separate from synced/exported app data.
- Host/user/port and explicit credential association remain checked; route changes do not invalidate credentials. Never choose by alias alone.
- Cloud failure cannot stop local signing or remove local usable credentials. Existing explicit browser mode remains compatible.
- Reuse existing SSH/crypto implementations; preserve user SSH Agent identities and remote authorized_keys.
- Desktop login recovery and unattended boot recovery must be described and tested separately. No claims of OS integration testing on unavailable platforms.
- Do not publish, push, delete recovery files, reboot the machine, or modify remote servers during implementation.

## Task 1: Route-independent identity and useful diagnostics

Files: `internal/ssh/local_identity.go`, `internal/ssh/local_identity_test.go`, `internal/cloudsync/load_agent.go`, its tests, `internal/ssh/client.go`, `internal/ssh/failure.go`, `internal/status/probe.go`, `internal/mcp/tools_read.go`, relevant tests.

Interfaces: existing `StoreLocalAgentIdentities`, `HasLocalAuth`, `matchingAgentEntry`, and `FailureCategory` continue to work. Add a shared route probe API in ssh if necessary; avoid dependencies on the new credential store.

- [x] Reproduce proxy-only mutation with a real test Agent: store exact target/public key, change only Proxy, assert signing still works. Assert changed host/user/port/vault/entry cannot use it.
  ```go
  require.NoError(t, StoreLocalAgentIdentities(path, target, []ssh.PublicKey{pub}))
  target.Proxy = "socks5://127.0.0.1:9999"
  require.True(t, HasLocalAuth(target, BuildOpts{ConfigPath: path}))
  ```
- [x] Run the new tests red, then implement a versioned target-bound cache (host/user/port/entry/vault, independent of routing); legacy exact-route cache can migrate after validation. Legacy direct cache may be looked up only by a fully reconstructed exact target with empty route fields, never by scanning arbitrary caches.
- [x] Update vault-to-target matching: with an explicit entry and owner binding, compare target host/user/port independent of route; native entries still require unique credential association. Keep wrong target/owner/fingerprint/delete/conflict rejection tests.
- [x] Add route-aware diagnostic tests: SOCKS forwarding to a local SSH fixture works even when the nominal direct target is unreachable. Probe results name their route; raw direct probe is not authoritative for proxy operations. Distinguish missing local credential from unavailable agent/malformed binding, and expose safe error codes in check_ssh.
- [x] Run focused tests, then affected package tests. Self-review only touched files; report RED/GREEN evidence, file list and any compatibility concerns. Do not change `internal/commands/cloud_link.go` (owned by integration task).

## Task 2: Device-protected local credential store

Files: new `internal/devicekey/` and `internal/localstore/` packages, platform adapters and behavior tests.

Interfaces:
```go
// devicekey protects opaque bytes using a platform mechanism; no plaintext fallback.
type Protector interface {
    Seal(context.Context, string, []byte) (backend string, blob []byte, err error)
    Open(context.Context, string, string, []byte) ([]byte, error)
}
// localstore associates credentials with explicit target identity and key fingerprint.
// ConfigPath scopes storage, file locking, wrapping context and service identity.
```

- [x] Test encrypted round-trip after a fresh Store instance, wrong wrapping key, tampering, config-instance mismatch, concurrent update, plaintext absence, explicit lock persistence and no overwrite after failed decrypt.
- [x] Implement versioned AES-GCM envelope with random data key/nonce and authenticated context; wrap data key with OS protection. Encrypt key/password/passphrase/cloud session fields. Atomic private-file writes and existing platform locking semantics preserve old store on failure.
- [x] Linux: user-scoped systemd credentials with noninteractive commands; Secret Service fallback for initial setup only, persisting selected backend. macOS: native CGO Security.framework Keychain API with noninteractive reads, never secret command arguments; no-CGO returns unsupported explicitly. Windows: user DPAPI with UI forbidden. Unsupported backend fails explicitly without weaker encryption fallback.
- [x] Credentials are validated by parsing the private key and deriving public fingerprint before accepting an import. A stored credential references canonical target host/port/user, not proxy or display alias. Separate cloud secret namespace from target credentials.
- [x] Run focused tests and cross-compile the packages for macOS/Windows. Real native backend verification is reported separately from test-protector integration tests.

## Task 3: Shared local resolution, import and cloud-token migration

Files: `internal/ssh/client.go`, `internal/commands/{cloud.go,cloud_link.go,genkey.go,pair.go,key_passphrase.go}`, `internal/cloudsync/{client.go,load_agent.go}`, new bridge files and tests.

Interfaces: localstore reads validated per-target credentials; SSH builds in-memory signers/password auth and releases plaintext after parsing. Existing local external key/Agent paths remain fallback when the store has no matching managed credential. Explicit device lock never falls back around the lock.

- [x] Add real SSH tests: persist encrypted target identity, destroy first in-memory signer/Agent, use a fresh MCP/CLI resolver and authenticate without cloud requests; password auth is also supported.
- [x] On trusted local unlock/import, persist independently usable credentials before loading compatibility Agent. Report unusable encrypted source keys accurately; preserve source files. Newly created managed keys store their generated protection material without a per-key user prompt.
- [x] cloudOpen first attempts device-protected master for the pinned account/vault. Initial local interactive unlock remembers it and verifies reopening. Cloud-only account changes or rekey cannot pick another account's wrapper.
- [x] State.Save migrates tokens into protected storage after verifying the saved value; State.Load reads protected token references. A failure does not silently overwrite usable state. Existing legacy files remain readable and an explicit migration command upgrades them with a private backup.
- [x] Test logout clears cloud token/master references and leaves independent SSH identities; lock blocks managed SSH across restart; malformed/missing credentials have exact recovery messages, never a generic cloud-unlock instruction.

## Task 4: Managed local service and cloud failure isolation

Files: new `internal/localservice/`, `internal/commands/service.go`, root/MCP integration, `internal/commands/cloud_link.go`, service installation templates and tests.

- [x] Test process restart and stale socket recovery with isolated config; two clients share a managed service, socket ownership is checked, startup is bounded and concurrent starters do not replace an active listener.
- [x] Add `sshm service run/install/status/lock/unlock` commands. Platform service definitions use an absolute executable/config, restart policy and protected files, and run as the same OS user. Explicit lock is persisted; no passwords are accepted in flags or tool arguments.
- [x] Service restores managed credentials from the local store independently of cloud connectivity. Agent compatibility identities have no artificial 12-hour expiry; external agent identities/constraints are preserved. Consumers can use local resolver without waiting for sync.
- [x] Change cloud loop 401/403/token changes to report sync state/backoff, preserving local availability. Unlocked local keys reload before network requests; cancellation is still prompt. Existing sync/signature/conflict semantics stay intact.
- [x] Add integration tests for cloud 401/timeouts, local signing after service restart, and real CLI/MCP independent processes. OS reboot is not performed automatically; explicitly record validation limits.

## Task 5: Docs, review and deliverable

Files: approved spec status, README, `docs/{security,cloud-sync,ai-integration}.md`, plugin cloud guidance, implementation record.

- [x] Update command examples and explain local device trust, encryption boundary, one-time migration, desktop versus headless startup, logout versus lock, network errors and independent sync.
- [x] Run relevant full Go tests, race tests for new concurrent code, Linux build and macOS/Windows cross-build. Run existing cloud/browser tests if their source or fixture behavior is affected.
- [x] Independent code review of identity binding, crypto/storage lifecycle, migration, cancellation and service ownership. Address important findings and rerun only affected checks.
- [x] Copy only new/modified refactor files to original checkout, retaining unrelated edits. Build reviewable binary and run read-only local diagnostics against temporary copied config before considering local activation; no secrets in artifacts.
- [x] Report what is implemented, what was verified, remaining OS verification limits, and whether installed runtime was changed. Do not claim a migration was performed if it needs unavailable original unlock material.

## Execution decisions

- User approved the architecture and implementation. Routine worktree/test choices do not require another approval.
- Local consumers share one credential resolver; forwarding every existing CLI/transfer operation through a new RPC protocol is unnecessary for the requested behavior and would increase migration risk. Service owns background restoration/sync; direct per-process resolution from the same protected store remains available for resilience.
- Localstore must not import `internal/ssh` or `internal/cloudsync` to avoid import cycles. It may use config models and x/crypto primitives. SSH/cloudsync adapters own their respective conversion logic.
- Worktree commit metadata may require sandbox escalation; only explicit refactor files can be staged. No unrelated work is committed.

- Native Linux systemd-user protection was verified with fresh CLI/MCP/service subprocesses. The process test does not claim a real OS reboot, a 12-hour soak, or native macOS/Windows validation.
- The macOS backend requires a native CGO build. Existing CGO-disabled release artifacts cannot provide it; native release packaging/validation is a follow-up before claiming macOS rollout.
- User-level startup templates are implemented; system-wide service installation deliberately returns unsupported. No service manager was installed into the user's real account during verification.
- The independent service worker handles cloud backoff and safe sync status; the legacy web-shell/cloud-agent compatibility lifecycle remains separate and cannot veto direct local credentials.
- Old plaintext-token state is backed up inside the encrypted cloud namespace before replacement. Source keys remain intact. This is not a full rotating credential-backup subsystem.
- The approved delivery is a scoped file copy into the original dirty checkout, not a branch merge or push. Preserve the implementation worktree for review.
