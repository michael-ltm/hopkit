---
name: sshm-server-ops
description: Use when the user asks to manage a server, deploy code, run a remote project build, package a Windows EXE, transfer or verify an artifact, inspect status or logs, restart a service, execute a remote command, add an SSH host, or bootstrap a machine.
---

# sshm Server Operations

Use sshm MCP tools instead of raw `ssh`. They preserve auditing, secret masking,
the dangerous-command filter, and host-key verification.

## Choose the narrowest tool

- Inventory and health: `list_servers`, `get_server`, `get_status`.
- Real SSH readiness: `check_ssh`; `test_connection` proves TCP reachability only.
- Project profiles: `list_projects`, then `get_project` for the full profile.
  Create or correct a user-confirmed profile with `upsert_project`.
- Commands: use `exec_project` for a configured project and `exec` / `exec_multi`
  for server-only work.
- Files: `upload` / `download`; use `transfer_start` / `transfer_status` when a
  large transfer could exceed one tool call.
- Operations: `tail_logs`, `bootstrap`, `gen_key`, `copy_id`.

## Operating contract

1. For an existing alias, run one `check_ssh` preflight with `mode=exec` before
   the first SSH-dependent command or mutation. Initial `add_server` is exempt;
   preflight after the alias exists. Reuse the result unless connectivity changes.
2. When a request names a project, build, workspace, run, or artifact, reuse its
   profile. Never infer a local path, remote workspace, run root, artifact path,
   shell, build command, or verification command. If required data is absent,
   ask the user; then call `upsert_project` with a specific `reason`.
3. Pass a clear `reason` to every write, command, transfer, and log operation.
4. Errors: surface the exact masked error; **do not retry the same failed mutation blindly**.
   Switch to read-only diagnosis such as
   `get_status`, `check_ssh`, or `tail_logs`, then change the plan from evidence.
5. Never set `unsafe=true` without explicit confirmation of the destructive
   command. Never expose private-key bytes, passphrases, or recovery contents.
6. TOFU pins unknown hosts. A **changed host key** may indicate MITM: stop and
   ask the user to verify it; never bypass verification without confirmation.
7. Relay `copy_id`'s CLI instruction verbatim; passwords stay outside AI tools.

## Conditional references

Read only the relevant file; do not preload every reference:

- Remote project build, deployment, Windows EXE packaging, or artifact transfer:
  [project-workflows.md](project-workflows.md)
- New host, key installation, provisioning, or SSH hardening:
  [onboarding.md](onboarding.md)
- Exact tool arguments and result shapes:
  [quick-reference.md](quick-reference.md)
- Server-only deploy and diagnostic sequences:
  [ai-patterns.md](ai-patterns.md)
