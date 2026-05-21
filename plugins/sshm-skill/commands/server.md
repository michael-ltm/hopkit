---
description: Manage SSH servers via sshm — list, status, connect, exec.
---

Use the sshm MCP tools to handle the user's request: "$ARGUMENTS".

Start by calling `list_servers` to see what is configured, then choose the
right tool. Follow the rules in the sshm-server-ops skill: pass a `reason`
to every write/exec tool, inspect before mutating, and never use
`unsafe: true` without explicit confirmation.
