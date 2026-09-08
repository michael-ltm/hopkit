# Optional cloud sync and updates

Use only with a cloud-enabled SSHM client. `sshm cloud status` is safe to inspect;
cloud setup, unlock and credential entry require the user's own interactive
terminal. Never ask the user to put account passwords, vault phrases, recovery
codes, SSH private keys or passwords in chat, tool arguments, environment
variables or AI-visible logs.

- Existing MCP tools continue to operate the original local inventory. Cloud
  records use `sshm cloud list/connect/exec`; do not claim MCP has unlocked them.
- `cloud register/login --username <name> --import-local` encrypts locally and
  merges existing records. Original configuration remains intact.
- `cloud presence` reports online status only. It does not authorize remote Shell.
- `cloud watch` holds an unlocked vault in its process and syncs periodically.
- `cloud conflicts` preserves conflicting records. Do not choose credentials or
  delete same-name records based only on alias; retain different users/routes.
- `sshm update --check` verifies the signed release feed. Installing an update
  needs explicit user intent or the CLI confirmation; do not set `--yes` merely
  to bypass the question. Existing signed updates may refresh only SSHM-managed
  integrations. Plugin-managed or locally edited skill files stay untouched.
- `sshm integrations status` inspects setup. Use `integrations install --app
  codex|claude|all` only when requested. MCP registration is a separate `--mcp`
  option, using each app's own CLI; never replace another server configuration.
