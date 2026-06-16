# sshm MCP Tool Quick Reference

| Tool | Required args | Optional args | Returns |
|---|---|---|---|
| `list_servers` | — | — | `{servers: [{alias, host, user, tags, last_status}]}` (sorted by alias) |
| `get_server` | `alias` | — | full record (host masked) |
| `test_connection` | `alias` | — | `{reachable, latency_ms, error}` |
| `get_status` | `alias` | — | `{status: {uptime, load, memory, disk, open_ports, failed_logins}}` |
| `add_server` | `alias`, `host`, `reason` | `user`, `auth` (default agent), `port`, `key_path`, `proxy`, `proxy_jump`, `proxy_command` | `{added: true}` |
| `edit_server` | `alias`, `reason` | `host`, `user`, `port`, `auth`, `key_path`, `proxy`, `proxy_jump`, `proxy_command` | `{updated: true}` |
| `remove_server` | `alias`, `reason` | — | `{removed: true}` |
| `exec` | `alias`, `command`, `reason` | `unsafe`, `timeout_seconds` (0 = no timeout, default 60), `detach` | `{exit, stdout, stderr}`; on timeout adds `timed_out: true`; large output adds `truncated: true`; with `detach` returns `{detached, log_path}` |
| `exec_multi` | `aliases[]`, `command`, `reason` | `unsafe`, `timeout_seconds` | `{results: {alias: …}, succeeded: […], failed: {alias: reason}}` |
| `upload` | `alias`, `local_path`, `remote_path`, `reason` | — | `{uploaded: true, bytes}` |
| `download` | `alias`, `remote_path`, `local_path`, `reason` | — | `{downloaded: true, bytes}` |
| `bootstrap` | `alias`, `reason` | — | `{completed, sshd_state}` |
| `gen_key` | `alias`, `path`, `reason` | — | `{key_path, public_key}` |
| `copy_id` | `alias`, `reason` | — | `{action_required: "<cli instruction>"}` |
| `tail_logs` | `alias`, `path`, `reason` | `lines` (clamped to [1, 5000]) | `{lines: "<masked tail>"}` |
