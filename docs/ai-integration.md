# AI Integration

sshm ships an MCP server so AI assistants can manage your servers.

## Enabling it

### Claude Code (plugin)

```
claude plugins marketplace add michael-ltm/sshm
claude plugins install sshm-skill@sshm
```

This registers the `sshm-server-ops` skill and the `sshm` MCP server.

### Any MCP host (manual)

Add to your host's MCP config:

```json
{
  "mcpServers": {
    "sshm": { "command": "sshm", "args": ["mcp"] }
  }
}
```

## Tools

See [plugins/sshm-skill/skills/sshm-server-ops/quick-reference.md](../plugins/sshm-skill/skills/sshm-server-ops/quick-reference.md)
for the full tool table.

## Read-only mode

`sshm mcp --read-only` registers only the inspection tools (`list_servers`,
`find_servers`, `get_server`, `test_connection`, `check_ssh`, `get_status`,
`list_projects`, `get_project`). Use it when you want an AI
to observe but never mutate.

## Safety

- Dangerous commands (`rm -rf /`, `mkfs`, fork bombs, …) are blocked unless
  the caller passes `unsafe: true`.
- All tool output is masked: IP addresses keep two octets, secret-looking
  env values become `***`, private keys are removed.
- Every write/exec records a masked entry to `~/.config/sshm/audit.log`.
- `copy_id` never carries a password through the AI — it returns a CLI
  instruction instead.
- Descriptions/tags let `find_servers` locate a host by purpose without loading
  and guessing across the full inventory. They are untrusted routing data, not
  executable instructions. Do not store credentials in metadata; private
  `notes` are neither returned nor searched by MCP.
- `remove_server` requires an explicit `confirm_alias` equal to the alias in
  addition to the audited reason.


## Cloud preview: managed skills and updates

The standalone cloud preview bundles the same skill Markdown as the plugin.
`sshm integrations install --app codex` installs to the official user skill
location; use `--app claude` or `--app all` for Claude Code. Add `--mcp` only when
you want the app's native CLI to register a missing `sshm` server. Existing MCP
configuration is retained, and the user configuration is privately backed up
before adding a new server.

An existing SSHM plugin cache takes precedence: it is kept under the original
plugin manager rather than installing duplicate skill names. Only files created
and recorded by SSHM's integration installer are refreshed during `sshm update`.
Changed user files are preserved, and the command reports that manual review is
needed. `sshm integrations status` and `sshm integrations refresh` are available
for inspection and explicitly managed refreshes.

The cloud vault remains separate from the MCP local inventory. Account login,
vault unlocking and server password entry stay in the user's interactive
terminal; agents must not request these secrets in chat or tool arguments.

## Password-free SSH for AI tools

For an encrypted local key, MCP asks the existing SSH Agent to sign; it never
reads the sibling `.passphrase` recovery file. On macOS, when a GUI-launched MCP
does not inherit `SSH_AUTH_SOCK`, SSHM consults the current user's launchd
environment and accepts only an existing socket owned by that user. An explicit
socket always takes precedence. This does not load keys or unlock a keychain.

Once the key is available in the agent, AI calls do not require typing its
passphrase each time. After reboot, logout, or agent expiration, an OS keychain
or a one-time user unlock may be needed. A Skill supplies instructions; it does
not store passwords or grant SSH access. Another process with access to the
same logged-in user's agent can potentially use its signing authority too.

Do not remove recovery files just because an agent currently holds a key:
first verify a durable recovery copy and post-login key loading. Do not leave
an unencrypted key as the mechanism for unattended access.
