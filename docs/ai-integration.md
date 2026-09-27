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

Default MCP and CLI share device-protected local credentials. New keys from
`gen_key` need no secret input: the device saves their generated protection
material before writing the encrypted key file. `passphrase_file` remains optional.

Migrate legacy credentials once with `sshm service setup` in your own terminal,
then `sshm service install` for background startup. Setup automatically uses safe
legacy recovery sidecars and reports unavailable identities without stopping
other imports. Use `sshm service setup --ask-passphrases` only when you know a
missing SSH secret; empty input skips it. Multiple MCP processes reuse the same store;
cloud network failures and token expiry do not gate local SSH. `service status`
shows local readiness. A stopped service does not prevent direct CLI/MCP recovery.

Treat `local_device_locked` as an explicit user choice: only a local
`sshm service unlock` clears it. Missing credentials need migration/registration;
network errors need route diagnosis, not repeated cloud unlock. Proxy changes do
not change credential identity. Explicit `--cloud-auth browser` retains its
separate online approval policy; it is optional.

Native key files and external Agents still work. Do not remove recovery files
merely because an Agent holds a key. Device encryption protects copied SSHM data;
it does not prevent programs already acting as the same logged-in user from
using that user's credentials. See [local trust and migration](cloud-sync.md#默认本地-ssh-与本机信任).
