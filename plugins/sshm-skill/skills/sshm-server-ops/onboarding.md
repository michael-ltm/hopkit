# Secure Server Onboarding

Default to key authentication. Passwords may be needed interactively for key
installation, but must never enter an AI tool call or chat.

1. Check `list_servers` / `get_server` so an existing host is not duplicated.
2. Call `add_server` with `auth=key`, the confirmed host details, and a specific
   `reason`. Configure proxy, jump host, or proxy command only when required.
3. Choose one key-install path; do not combine them:
   - **MCP-assisted:** call `gen_key` with a user-confirmed key path, relay
     `copy_id`'s CLI instruction verbatim, then run one `check_ssh mode=exec`.
   - **All-in-one CLI:** before generating a key, have the user run
     `sshm provision <alias> --harden`. It generates, installs, tests, and only
     then disables password login. Do not run it after `gen_key`; it starts by
     generating a new key and will fail when that key path already exists.
4. `gen_key` creates a passphrase-encrypted ed25519 key, attempts OS
   keystore/agent persistence, and returns a `recovery_file` path without the
   passphrase. Never read or echo private-key, passphrase, or recovery contents.
5. `bootstrap` applies baseline tooling but does not disable password login.

The one-shot server password stays in the user's terminal. TCP reachability
alone does not prove authentication or command execution.

If a key already exists, do not regenerate it blindly. Diagnose agent/key
availability and follow the tool's error. A changed host key is a separate trust
failure: stop and ask the user to verify the new fingerprint before any bypass.
