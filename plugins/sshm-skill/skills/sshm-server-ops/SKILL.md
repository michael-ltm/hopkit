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
- `test_connection` — quick reachability probe.
- `add_server` / `edit_server` / `remove_server` — manage the inventory.
  Every write needs a `reason` and is recorded to the audit log.
- `exec` / `exec_multi` — run commands. Dangerous commands (`rm -rf /`,
  `mkfs`, …) are blocked unless `unsafe: true` is passed. Always supply a
  `reason`.
- `bootstrap` — baseline-harden a fresh server.
- `gen_key` — generate an ed25519 keypair for a host.
- `copy_id` — returns CLI instructions; copy-id needs a password, which is
  never sent through the AI.
- `tail_logs` — read the tail of a remote log file.

## Rules

1. Prefer `get_status` / `test_connection` before acting on a server.
2. Always pass a clear, specific `reason` to write/exec tools.
3. Never pass `unsafe: true` unless the user explicitly confirms the
   destructive command.
4. If a tool returns `{"error": ...}`, surface the message to the user and
   stop — do not retry blindly.
5. For `copy_id`, relay the returned CLI instruction to the user verbatim.

See [quick-reference.md](quick-reference.md) and [ai-patterns.md](ai-patterns.md).
