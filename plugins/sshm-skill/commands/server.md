---
description: Manage SSH servers via sshm — list, status, connect, exec.
---

Use the sshm MCP tools to handle the user's request: "$ARGUMENTS".

If the user names an alias, call `get_server`; if they describe a purpose or
capability, call `find_servers`; use `list_servers` only for full inventory or
ambiguity. Follow the rules in the sshm-server-ops skill: pass a `reason`
to every write/exec tool, inspect before mutating, and never use
`unsafe: true` without explicit confirmation.
