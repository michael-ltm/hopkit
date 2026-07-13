# Changelog

All notable changes to this project will be documented in this file. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.6.0] — 2026-07-13

### Added
- Version-3 project profiles with stable local root, remote workspace/run root, artifact path, shell, build command, and verification command fields. New MCP tools `list_projects`, `get_project`, and audited `upsert_project` expose those profiles without guessing paths.
- `exec_project` runs commands in a profile's `workspace`, `runs`, or `artifact_parent` directory while preserving the existing dangerous-command filter, timeout/detach behavior, masking, audit reason, and host-key verification.

### Changed
- Detached jobs and `tail_logs` are cross-platform: Windows launch results expose concrete PID/log metadata, while log reads accept `platform=auto|posix|windows` and use the remote platform's native command.
- The `sshm-server-ops` skill now uses conditional references for project builds, Windows EXE packaging, artifact verification, and onboarding. Its always-loaded core fell from 642 to 383 words; the common project path is 1040 words (383 core + 657 workflow) instead of the previous 1199-word default load.
- Compatibility remains additive: version-2 configuration files load without implicit migration and upgrade only when saved, and existing server-only CLI/MCP tool names and behavior remain available.

## [0.5.1] — 2026-07-09

### Added
- `check_ssh` MCP tool for layered diagnostics: TCP reachability, SSH auth/handshake, and a minimal `hostname` exec check. This avoids treating an open port as proof that remote commands can run.
- Background MCP transfers via `transfer_start` and `transfer_status`, so large uploads/downloads can continue outside a single tool-call timeout and be polled by transfer id.
- CLI `sshm upload` and `sshm download` commands for direct SFTP file transfer with `--resume`, `--sha256`, and `--timeout`.

### Changed
- MCP `upload` / `download` now write through `.part` files, support `resume: true`, return SHA-256, and atomically rename after a successful transfer.
- `exec detach` can auto-detect Windows remotes and launch detached commands through PowerShell instead of assuming a POSIX shell.

### Fixed
- The dangerous-command filter no longer blocks benign `/dev/null` redirections like `2>/dev/null` and `>/dev/null`, while still blocking redirects to real device nodes and system paths.

## [0.5.0] — 2026-07-04

### Added
- Secure-by-default key provisioning. `gen_key` (CLI and MCP) now generates a **passphrase-encrypted** ed25519 key, stores the passphrase in the OS keystore (macOS login keychain via `ssh-add --apple-use-keychain`; Windows OpenSSH agent / DPAPI; Linux ssh-agent, session-only), and writes a `0600` recovery file. The MCP result returns only a recovery-file pointer — never the passphrase.
- `sshm provision <alias> [--harden]` — one command to generate an encrypted key, install it (one-shot password on the CLI), verify key auth, and optionally disable password login on the server. `--harden` refuses to run unless the connectivity test passed, and verifies via `sshd -T` that password auth is actually off before reporting success.
- `internal/keystore` package: cross-platform passphrase storage + agent loading, reusing the per-OS agent dialer.

### Changed
- `sshm gen-key` encrypts by default; pass `--no-encrypt` for the old plaintext behaviour. Agent/keystore loading is best-effort — a headless host with no agent still generates and registers the encrypted key (reported as not-persisted) rather than failing.

## [0.4.1] — 2026-07-03

### Added
- Encrypted (passphrase-protected) private keys now work with `auth = "key"`: when the key file is encrypted, sshm resolves the matching identity from the running ssh-agent by exact public-key match — a keychain-backed agent signs without sshm ever handling the passphrase. Only that one identity is offered, so a server's `MaxAuthTries` is never exhausted by unrelated agent keys.
- Windows: ssh-agent support via the `\\.\pipe\openssh-ssh-agent` named pipe (the "OpenSSH Authentication Agent" service) for both `auth = "agent"` and the encrypted-key fallback.
- Legacy PEM-encrypted keys (no embedded public key): the identity for the agent lookup is recovered from the sibling `.pub` file.

### Changed
- New dependency: `github.com/Microsoft/go-winio` (Windows named-pipe dialing; non-Windows builds unaffected).

### Fixed
- Plugin distribution: the repo now has a proper `.claude-plugin/marketplace.json` so `claude plugins marketplace add michael-ltm/sshm` works. The plugin manifest moved to `.claude-plugin/plugin.json` and the MCP registration to `.mcp.json` per the Claude Code plugin format.

## [0.4.0] — 2026-06-16

### Added
- Proxy/VPN-aware SSH dialing with transport precedence: `proxy_command` > `proxy_jump` > `proxy` (SOCKS5) > direct.
- `proxy_command`: runs a shell command as the transport; supports `%h`/`%p`/`%r` substitution (e.g. `nc -X 5 -x 127.0.0.1:7890 %h %p`).
- `proxy_jump`: single-hop jump host — an existing sshm alias or `[user@]host[:port]`.
- `proxy`: per-host SOCKS5 URL (`socks5://[user:pass@]host:port`); authenticated SOCKS5 supported.
- Zero-config SOCKS5: if no `proxy` is set, sshm auto-detects a local proxy from env vars `ALL_PROXY`, `SOCKS5_PROXY`, `HTTPS_PROXY` (upper- and lower-case) — works out of the box behind a local VPN or proxy.
- Retry / fallback: if a proxy or jump-host attempt fails, sshm automatically retries via a direct connection (covers TUN/VPN-active environments).
- `add_server` / `edit_server` MCP tools gained optional `proxy`, `proxy_jump`, and `proxy_command` args.

### Changed
- New dependency: `golang.org/x/net` (SOCKS5 dialer).

## [0.3.0] — 2026-06-16

### Added
- `upload` / `download` MCP tools — move single files between the local machine and a server over SFTP (returns `{uploaded/downloaded, bytes}`; never returns file content).
- `exec`: new optional `timeout_seconds` arg (0 = no timeout, default 60); on timeout, captured partial output is returned with `timed_out: true`. New `detach` arg runs the command in the background on a POSIX remote and returns a `log_path` to poll with `tail_logs`.
- `exec_multi` now runs concurrently (bounded); returns `{results, succeeded, failed}` instead of a flat map.

### Changed
- `list_servers` results are now sorted by alias.
- `tail_logs`: `lines` arg is clamped to [1, 5000].
- `gen_key`: automatically sets `auth=key` on the server record; surfaces save errors instead of silently discarding them.
- MCP server version now reflects the build version (set via ldflags at release).

### Fixed
- Concurrency: config read-modify-write serialised via `config.Update`; audit log appends are locked — eliminates lost-update races under mcp-go's worker pool.
- All read/ops MCP handlers now honour the request context (cancellation propagates correctly).
- `ProbeMany` stops launching new probes when its context is cancelled.

### Security
- Host-key verification via TOFU by default: unknown hosts are pinned to `~/.ssh/known_hosts` (accept-new); known hosts are verified; a changed key is rejected as a potential MITM. Pass `--insecure` on `exec`/`connect` to opt out. MCP tools always verify.
- `MaskSecrets` broadened to cover kv/env secrets, password flags, GitHub/AWS/Slack tokens, JWT, Bearer tokens, and IPv6 addresses (previously IPv4 + PEM only).
- `IsDangerous` broadened to cover pipe-to-shell patterns, `rm -rf` of absolute/home paths, `find -delete`, `dd of=/dev/*`, `shred /dev/*`, `chmod/chown -R /`, and redirects onto system files — without flagging relative-path or `/tmp` operations.

## [0.2.0]

### Added
- `sshm mcp` — built-in MCP server exposing 13 tools for AI assistants.
- `sshm status` — remote resource snapshot (uptime, load, memory, disk).
- `sshm init` — baseline server hardening (installs fail2ban, reports sshd state).
- `internal/safety` — dangerous-command filter, secret masking, audit log.
- Claude Code plugin `sshm-skill` (install: `claude plugins marketplace add michael-ltm/sshm` then `claude plugins install sshm-skill@sshm`).
- `docs/ai-integration.md`, `docs/security.md`.

## [0.1.0]

### Added
- Initial project scaffold.
