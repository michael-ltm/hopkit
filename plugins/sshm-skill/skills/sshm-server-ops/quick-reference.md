# sshm MCP Tool Quick Reference

| Tool | Required args | Optional args | Returns |
|---|---|---|---|
| `list_servers` | — | — | `{servers: [{alias, host, user, tags, last_status}]}` |
| `get_server` | `alias` | — | full record (host masked) |
| `test_connection` | `alias` | — | `{reachable, latency_ms, error}` |
| `get_status` | `alias` | — | `{status: {uptime, load, memory, disk, open_ports, failed_logins}}` |
| `add_server` | `alias`, `host`, `reason` | `user`, `auth` (default agent), `port`, `key_path` | `{added: true}` |
| `edit_server` | `alias`, `reason` | `host`, `user`, `port`, `auth`, `key_path` | `{updated: true}` |
| `remove_server` | `alias`, `reason` | — | `{removed: true}` |
| `exec` | `alias`, `command`, `reason` | `unsafe` | `{exit, stdout, stderr}` |
| `exec_multi` | `aliases[]`, `command`, `reason` | `unsafe` | `{results: {alias: …}}` |
| `bootstrap` | `alias`, `reason` | — | `{completed, sshd_state}` |
| `gen_key` | `alias`, `path`, `reason` | — | `{key_path, public_key}` |
| `copy_id` | `alias`, `reason` | — | `{action_required: "<cli instruction>"}` |
| `tail_logs` | `alias`, `path`, `reason` | `lines` | `{lines: "<masked tail>"}` |
