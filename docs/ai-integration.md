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
