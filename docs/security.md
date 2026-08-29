# Security

## Credential handling

- Passwords are never written to `config.toml`. `copy-id` reads a password
  from the TTY for a single operation and zeroes the buffer afterward.
- Private keys are never read except when about to be used, never logged,
  and never returned through the MCP server. Generated private keys and
  passphrase-recovery files use `0600` on POSIX and a protected DACL granting
  access only to the current user and LocalSystem on Windows.
- `config.toml` and `audit.log` are written with mode `0600`.
- `pair` embeds only a public key and random one-time callback token in the
  target command. The callback is accepted once, validates bounded fields, and
  a new alias is not persisted until a separate key-authenticated SSH session
  confirms `whoami` and `hostname`.
- Pairing auto-selects only loopback/private/Tailscale callback addresses;
  public and common TUN fake-IP routes, explicit public IP literals, and IPv6
  link-local addresses are rejected. Link-local IPv6 needs an interface zone
  that the portable target command cannot preserve safely. Explicit hostnames
  that resolve locally are also rejected if any result is public, a common TUN
  fake IP, or IPv6 link-local; an unresolved MagicDNS/LAN name must still be
  confirmed reachable from the target.
  Generated command files requested with `--script-dir` use `0600` on POSIX
  and the same protected current-user/LocalSystem DACL on Windows.
- Before emitting a target command, pairing exercises a real signature with
  the selected key and verifies it locally. The Windows download fallback is
  version-pinned, verifies the whole official ZIP against a compiled SHA-256,
  and checks the extracted `sshd.exe` Microsoft Authenticode signature before
  running the bundled installer.

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
- Guided cleanup starts with no records selected and requires a final
  confirmation. It protects the default server, project references, ProxyJump
  references, and manually protected records; legacy records with unknown
  history are excluded unless explicitly requested.
- Cleanup creates and syncs a private config backup before changing the
  inventory (`0600` on POSIX; a protected current-user/LocalSystem DACL on
  Windows) and removes only config records. It never deletes local private
  keys, `known_hosts`, or remote `authorized_keys` entries.

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
