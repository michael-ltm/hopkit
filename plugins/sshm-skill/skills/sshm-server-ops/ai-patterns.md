# sshm AI Patterns

Common multi-step workflows expressed as sshm tool sequences.

## Deploy code to a server

1. `test_connection` — confirm the host is up.
2. `exec` with `command: "cd /var/www/app && git pull"`, a `reason`.
3. `exec` with `command: "systemctl restart app"`.
4. `get_status` — confirm the service is healthy.

## Onboard a fresh server

1. `add_server` with the host details and a `reason`.
2. `gen_key` to create a dedicated keypair.
3. Relay the `copy_id` instruction to the user (they run it in a terminal).
4. `test_connection` to confirm key auth works.
5. `bootstrap` to install baseline tooling.

## Investigate a slow server

1. `get_status` — look at load, memory, disk.
2. `tail_logs` on the relevant service log.
3. `exec` with read-only diagnostics (`ss -s`, `journalctl -p err`).

## Rules of thumb

- One `reason` per write, specific to the change.
- Read before write: inspect with `get_status` / `tail_logs` first.
- Never escalate to `unsafe: true` without explicit user confirmation.
