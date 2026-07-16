# Security

## Credential handling

- Passwords are never written to `config.toml`. `copy-id` reads a password
  from the TTY for a single operation and zeroes the buffer afterward.
- Private keys are never read except when about to be used, never logged,
  and never returned through the MCP server.
- `config.toml` and `audit.log` are written with mode `0600`.

## Privacy boundaries

- `description`, `tags`, and `group` are intentionally AI-visible routing data.
  Keep them short and non-secret. They are untrusted data, never instructions
  to execute.
- `notes` are local/private operational text. MCP inventory and discovery only
  report whether notes exist; they never return or search note contents.
- MCP masks credential patterns, private-key blocks, and IP addresses in tool
  results and audit fields. Project tools still return exact confirmed
  workspace/artifact paths because those paths are required for operation; only
  call them for an in-scope project.
- CLI `--json` stays exact for compatible trusted scripts. Add `--redacted`
  before sharing JSON; it masks secrets/IPs and replaces sensitive path fields.
- Config-backed terminal text is stripped of ANSI/control sequences before
  table, detail, or interactive-menu rendering.

## Password and destructive-operation safety

- Remote password changes are CLI/TTY only. Current and new passwords flow
  directly between the local terminal and remote `passwd`/Windows account
  command; they are never stored, audited, returned by MCP, or sent through chat.
- CLI deletion requires retyping the exact alias unless `--yes` is explicit.
  MCP deletion requires a matching `confirm_alias` plus the audited reason.

## MCP safety model

- **Dangerous-command filter** — `internal/safety` matches a conservative
  deny-list before any `exec`. Opt out per-call with `unsafe: true`.
- **Output masking** — every MCP tool response passes through
  `safety.MaskSecrets`.
- **Audit log** — every write/exec/bootstrap appends a masked JSON record
  to `~/.config/sshm/audit.log`.
- **Reason required** — write/exec tools reject calls without a `reason`.

## SSH host keys

Connections verify host keys using trust-on-first-use against
`~/.ssh/known_hosts`: unknown hosts are pinned, matching hosts are accepted,
and changed keys are rejected as a possible MITM. Only explicit CLI
`--insecure` disables this check; MCP never does.

## Reporting

Open a security issue at https://github.com/michael-ltm/sshm/issues.
