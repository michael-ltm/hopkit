---
name: sshm-server-ops
description: "Use for SSH server operations through sshm MCP: status, commands, deploys and builds (including Windows EXE), artifact transfer, services, onboarding, or hardening."
---

# sshm Server Operations

Use sshm MCP, not raw `ssh`, to retain auditing, masking, command filtering,
and host-key verification.

## Tool routing

- Inventory/health: `list_servers`, `get_server`, `get_status`; `check_ssh`
  proves real SSH readiness, while `test_connection` proves TCP only.
- Named project: call `get_project` directly; `list_projects` only discovers
  names or resolves initial ambiguity. Confirm changes before `upsert_project`.
- Commands: `exec_project` for profiles; `exec` / `exec_multi` otherwise.
- Files: `upload` / `download`; large transfers use
  `transfer_start` / `transfer_status`. Other operations: `tail_logs`,
  `bootstrap`, `gen_key`, `copy_id`.

## Operating contract

1. Before an existing alias's first SSH-dependent action, run one
   `check_ssh(mode=exec)` and reuse it unless connectivity changes. For
   `add_server`, check after creation.
2. Resolve a named project once and reuse it. If direct lookup is unknown, use
   the returned names; do not call `list_projects` again. Never infer paths,
   shell, build, or verification commands. Ask for missing values, then
   `upsert_project` with a reason.
3. Give every write, command, transfer, and log call a specific `reason`.
4. Surface the exact masked error; **do not retry the same failed mutation blindly**.
   Diagnose read-only (`get_status`, `check_ssh`, `tail_logs`) and adapt from evidence.
5. Set `unsafe=true` only after explicit confirmation of that destructive
   command. Never expose key bytes, passphrases, passwords, or recovery data.
6. A **changed host key** may be MITM: stop for user verification; never bypass
   it silently. Relay `copy_id` instructions verbatim so passwords stay outside AI tools.

## Output discipline

Plans default to one short line per call, one failure line, and one completion
line; expand only when a gate would be ambiguous or the user asks. Include no
sample JSON, schema restatement, or repeated rationale. List only skill files
actually read. After execution, report evidence instead of narration.

## Conditional references

Read only the needed reference:

- Remote project build, deployment, Windows EXE packaging, or artifact transfer:
  [project-workflows.md](project-workflows.md)
- New host, key installation, provisioning, or SSH hardening:
  [onboarding.md](onboarding.md)
- Exact arguments/results only when live MCP information is insufficient:
  [quick-reference.md](quick-reference.md)
- Server-only deploy and diagnostic sequences:
  [ai-patterns.md](ai-patterns.md)
