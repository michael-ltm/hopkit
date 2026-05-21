# Security

## Credential handling

- Passwords are never written to `config.toml`. `copy-id` reads a password
  from the TTY for a single operation and zeroes the buffer afterward.
- Private keys are never read except when about to be used, never logged,
  and never returned through the MCP server.
- `config.toml` and `audit.log` are written with mode `0600`.

## MCP safety model

- **Dangerous-command filter** — `internal/safety` matches a conservative
  deny-list before any `exec`. Opt out per-call with `unsafe: true`.
- **Output masking** — every MCP tool response passes through
  `safety.MaskSecrets`.
- **Audit log** — every write/exec/bootstrap appends a masked JSON record
  to `~/.config/sshm/audit.log`.
- **Reason required** — write/exec tools reject calls without a `reason`.

## SSH host keys

v0.2 still uses trust-on-first-use (`InsecureIgnoreHostKey`). Strict
`known_hosts` verification is planned for a later release.

## Reporting

Open a security issue at https://github.com/michael-ltm/sshm/issues.
