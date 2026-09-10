# Local-first SSH with encrypted vault sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. The user has authorized implementation; proceed in this session.

**Goal:** Make local unlocked SSH identities reusable by CLI/MCP while retaining encrypted cloud synchronization.

**Architecture:** Default connection authentication uses local keys and an SSH Agent. Unlocking the cloud agent loads usable active vault identities and writes only route-bound public identity metadata. Per-process browser authorization remains opt-in.

**Tech Stack:** Go, golang.org/x/crypto/ssh and agent, existing cloudsync/config/MCP packages.

**Spec:** `docs/superpowers/specs/2026-09-10-local-first-vault.md`

## Global Constraints

- Preserve all pre-existing worktree changes; no broad resets, cherry-picks, or unrelated commits.
- No plaintext private key, passphrase, vault master or new recovery sidecar on disk/logs.
- Exact route/entry matching; no alias glob fallback.
- Keep host-key verification, auditing, masking, encrypted signed sync and optional browser mode.
- Do not restart the incident recovery helper or currently approved MCP while building.

## Task 1: Native SSH identity resolution

Files: `internal/ssh/local_identity.go`, its tests, `client.go`, `dial.go`, existing cloud-dial tests.

Interfaces:

```go
func StoreLocalAgentIdentities(configPath string, server *config.Server, pubs []gssh.PublicKey) error
func HasLocalAuth(server *config.Server, opts BuildOpts) bool
```

`StoreLocalAgentIdentities` writes public-only JSON in a private directory beside the config, named by a digest over full route, CloudEntry and CloudVault. Auth/key-path/alias are not identity selectors. Refuse symlink cache targets, oversized files and malformed public keys. `HasLocalAuth` exercises the same signer resolution and closes resources.

- [ ] Write failing tests: native key with CloudEntry works; cloud marker with exact cached public key and Agent works; different route/entry fails; no matching Agent fails with local-unlock guidance.
- [ ] Run `go test ./internal/ssh` and record intended failures.
- [ ] In `Dial`, resolve cloud bindings only when an explicit resolver is supplied. In `buildAuth`, remove the CloudEntry-only hard gate, preserve supplied signers/closers, and resolve AuthCloud using the exact public cache. Explicit browser resolver failures must never fall back.
- [ ] Run targeted real SSH/Agent tests, then the SSH package suite.

## Task 2: Unlock once and load usable vault identities

Files: new `internal/cloudsync/load_agent.go` and tests; `internal/commands/cloud_link.go`; minimal keystore support only if required.

Interface:

```go
type LoadReport struct { Loaded int; Skipped []string }
func LoadMatchingKeysIntoAgent(state *State, v *Vault, cfg *config.Config, configPath string) (LoadReport, error)
```

Consumes Task 1 `StoreLocalAgentIdentities`. Use the existing `loadAndProve`/agent APIs, parse private keys in memory, select active non-conflicted entries by exact CloudEntry/CloudVault or unique full route. Preserve native local paths. Never read arbitrary password credentials as speculative passphrases and never mutate encrypted keys. Keep loaded keys time-limited (12 hours) and preserve existing Agent keys. Report skipped encrypted credentials without secret contents.

- [ ] Write failing real Agent tests covering reusable signing, missing passphrase, deleted/conflicted entry exclusion, exact route selection and no private material written.
- [ ] Implement preload from `runCloudAgent` after local unlock and after successful fresh sync. Keep synchronization error behavior and shell lifecycle intact.
- [ ] Run cloudsync/keystore tests relevant to loading and signing.

## Task 3: Default local MCP and CLI, optional browser mode

Files: `internal/mcp/server.go`, `internal/commands/mcp.go`, `connect.go`, `exec.go`, matching tests and `docs/cloud-sync.md`.

- [ ] Add default `--cloud-auth local` and explicit `browser`; reject other values. Only browser mode creates CloudSession/registers cloud approval tools. Explicit injected CloudSession continues supporting existing tests and clients.
- [ ] Add failing tests that default MCP has local auth/no approval tools, browser mode retains its locked checks, and CLI can use an existing Agent without invoking vault prompts.
- [ ] Use `HasLocalAuth` before interactive vault fallback; noninteractive local failures explain `sshm cloud agent` and do not ask for passwords in tools.
- [ ] Update human documentation and skill guidance to explain the new default and encryption/lifecycle boundary.
- [ ] Review integration, run scoped MCP/commands/SSH/cloudsync tests, cross-compile Darwin/Windows, build and atomically install a backed-up local binary.

## Recovery remains separate

The temporary recovery helper has an active user-approved session. Do not execute its restore operation until credential-ID and alias-collision review findings are addressed or proven absent. Preserve the old encrypted vault backup at `~/.config/sshm/recovery-prod-20260910/`. Never claim restored connectivity from metadata restoration alone.
