---
name: sshm-server-ops
description: Use when the user asks to manage a server, deploy code, check server status, restart a service, run a remote command, add or inspect an SSH host, or bootstrap a fresh machine. sshm exposes these as MCP tools.
---

# sshm Server Operations

sshm is installed and its MCP server is registered. Use the sshm MCP tools
rather than raw `ssh` commands — they are audited, mask secrets, and block
dangerous commands.

## Available tools

- `list_servers` — see every configured server (host IPs are masked).
- `get_server` / `get_status` — inspect one server's config / live resources.
- `test_connection` — quick TCP reachability probe.
- `check_ssh` — layered TCP/auth/exec check; prefer this when you need to
  know whether commands can actually run.
- `add_server` / `edit_server` / `remove_server` — manage the inventory.
  Every write needs a `reason` and is recorded to the audit log.
  `add_server` and `edit_server` accept optional proxy args: `proxy`
  (SOCKS5 URL `socks5://[user:pass@]host:port`), `proxy_jump` (an existing
  alias or `[user@]host[:port]`), or `proxy_command` (shell command with
  `%h`/`%p`/`%r` substitution). A local SOCKS5 proxy is also auto-detected
  from `ALL_PROXY` / `HTTPS_PROXY` env vars (zero-config behind a VPN or
  local proxy). If a proxy or jump attempt fails, sshm falls back to a direct
  connection automatically.
- `exec` / `exec_multi` — run commands. Dangerous commands (`rm -rf /`,
  `mkfs`, …) are blocked unless `unsafe: true` is passed. `exec` supports
  `timeout_seconds` (0 = no timeout, default 60), `detach`, and optional
  `platform=auto|posix|windows` for detached launchers. Always supply a
  `reason`.
- `upload` / `download` — transfer a single file between the local machine
  and a server over SFTP (returns a byte-count summary, never file content).
  Use `resume=true` and `sha256` for large artifacts.
- `transfer_start` / `transfer_status` — background file transfer for large
  artifacts that may exceed a single MCP tool-call timeout.
- `bootstrap` — baseline-harden a fresh server.
- `gen_key` — generate an ed25519 keypair for a host.
- `copy_id` — returns CLI instructions; copy-id needs a password, which is
  never sent through the AI.
- `tail_logs` — read the tail of a remote log file (`lines` clamped to
  [1, 5000]).

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

## Rules

1. Prefer `get_status` / `check_ssh` before acting on a server.
2. Always pass a clear, specific `reason` to write/exec tools.
3. Never pass `unsafe: true` unless the user explicitly confirms the
   destructive command.
4. If a tool returns `{"error": ...}`, surface the message to the user and
   stop — do not retry blindly.
5. For `copy_id`, relay the returned CLI instruction to the user verbatim.
6. Host keys are verified via TOFU: unknown hosts are pinned on first connect;
   a changed key is rejected as a potential MITM. If a connection is refused
   due to a changed host key, surface the error to the user — do not pass
   `--insecure` without explicit confirmation.

See [quick-reference.md](quick-reference.md) and [ai-patterns.md](ai-patterns.md).
