# sshm MCP Tool Quick Reference

Mutations, commands, upload/download, `transfer_start`, and `tail_logs` require
a specific `reason`.

| Tool | Required args | Optional args | Returns |
|---|---|---|---|
| `list_servers` | — | — | compact servers sorted by alias |
| `find_servers` | `query` | `limit` (default 5, max 20) | ranked matches with description, tags/group, score, and matched fields |
| `get_server` | `alias` | — | full server record; host masked |
| `test_connection` | `alias` | — | `{reachable, latency_ms, error}`; TCP only |
| `check_ssh` | `alias` | `mode=tcp\|handshake\|auth\|exec` (default `exec`) | layered `{tcp, ssh, exec, ok}` |
| `get_status` | `alias` | — | uptime, load, memory, disk, ports, failed logins |
| `list_projects` | — | — | compact profiles sorted by project |
| `get_project` | `project` | — | complete project profile |
| `upsert_project` | `project`, `reason`; create also needs `server`, `remote_workspace`, `artifact_path` | profile fields on update; `local_root`, `remote_runs`, `local_artifact_dir`, `shell=auto\|posix\|powershell\|cmd`, `build_command`, `verify_command` | `{project, server, created, updated}` |
| `add_server` | `alias`, `host`, `reason` | connection fields; AI-visible `description`, `tags`, `group` | `{added}` |
| `edit_server` | `alias`, `reason` | discovery fields; connection/auth/key/proxy edits also require exact `confirm_alias`; empty description/group or `[]` tags clears them | `{updated}` |
| `remove_server` | `alias`, `confirm_alias`, `reason` | — | `{removed}`; alias must be unreferenced and confirmation must exactly match |
| `exec` | `alias`, `command`, `reason` | `unsafe`, `timeout_seconds` (0 = none), `detach`, `platform=auto\|posix\|windows` | exit/output; detach adds platform-specific `log_path` and may add `pid` |
| `exec_project` | `project`, `command`, `reason` | `workdir=workspace\|runs\|artifact_parent`, `unsafe`, `timeout_seconds`, `detach`, `platform` | exec result plus `{project, alias, workdir, shell}` |
| `exec_multi` | `aliases[]`, `command`, `reason` | `unsafe`, `timeout_seconds` | per-alias results and succeeded/failed sets |
| `upload` / `download` | `alias`, local/remote paths, `reason` | `resume`, `sha256` | byte counts, resume offset, SHA-256 |
| `transfer_start` | `alias`, `direction`, local/remote paths, `reason` | `resume`, `sha256` | transfer id and progress |
| `transfer_status` | `transfer_id` | — | state, byte counts, error, SHA-256 |
| `tail_logs` | `alias`, `path`, `reason` | `lines` (default 100, max 5000), `platform=auto\|posix\|windows` | `{alias, path, platform, lines}` or structured masked exec error |
| `bootstrap` | `alias`, `reason` | — | `{completed, sshd_state}` |
| `gen_key` | `alias`, `path`, `reason` | — | key metadata and recovery-file pointer; no passphrase |
| `copy_id` | `alias`, `reason` | — | terminal-only `action_required` instruction |

`upsert_project` is a partial update: omitted fields stay unchanged; an explicit
empty string clears an optional field. Project names match
`^[a-z0-9][a-z0-9._-]*$`.
