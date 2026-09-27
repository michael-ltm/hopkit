# Optional cloud sync and updates

Use only with a cloud-enabled SSHM client. `sshm cloud status` is safe to inspect;
cloud setup and credential entry require the user's own interactive
terminal. Default MCP uses device-protected local credentials, then existing native keys/Agents. Never ask the user to put account passwords, vault phrases, recovery
codes, SSH private keys or passwords in chat, tool arguments, environment
variables or AI-visible logs.

- In default `sshm mcp` / `--cloud-auth local` mode, execute the requested SSH
  operation using existing local credentials, including cloud-linked aliases.
  Paired/migrated credentials survive new MCP processes and local service restarts.
  Cloud connectivity and token expiry govern synchronization, not local SSH.
  Credential identity binds host, user, port and credential/vault association;
  changing a local proxy/jump route does not require credential approval.
- Inspect `sshm service status` when local access fails. If no local store exists,
  the one-time legacy migration is `sshm service setup` in the user's own terminal,
  followed by `sshm service install` for background startup. An old key still needs
  its original passphrase once if no decryptable vault copy exists. Never repeat
  setup/unlock as a generic fix: `local_device_locked` requires a deliberate local
  `sshm service unlock`; `local_credential_missing` requires registering that target;
  unavailable device protection requires fixing its OS backend. A stopped service
  does not block the shared direct CLI/MCP credential resolver.
- For timeout/refused/proxy errors, use `check_ssh` and its selected route;
  verify or correct the local transport. A failing direct probe does not prove
  a proxy route is broken. Do not request cloud login/unlock to fix network errors.
- `gen_key` automatically encrypts and persists a new key on the trusted device;
  `passphrase_file` is optional. Never create a plaintext passphrase sidecar or
  put a secret in tool arguments to work around setup errors.
- Keys, saved SSH passwords, cloud tokens and remembered vault masters are encrypted
  locally under OS protection. Account login passwords are not persisted.
  `cloud logout` clears cloud access while keeping independent local SSH credentials;
  `service lock` persists across restarts. Do not automatically unlock an explicit lock.
  Same-user programs can use the trusted local identity. Use explicit browser mode when online cloud authorization
  is required for each new cloud connection.
- Only in explicit `sshm mcp --cloud-auth browser` mode, when the cloud connection
  is locked and approval tools are present, call `cloud_unlock` with a brief non-secret
  reason. Present its approval URL and verification code to the user, who checks
  the code and approves MCP credential access in the trusted browser. Poll
  `cloud_unlock_status`; retry the requested operation only after its state is `ready`.
  Never ask for passwords, keys, recovery codes, root pins or endpoint overrides
  as tool inputs. Existing account setup and a pinned root are required.
- In browser mode, approval belongs to the requesting MCP process. Another MCP process, CLI
  `cloud link`, or `cloud watch` does not unlock this one. Do not start watch to
  fix a locked browser session. Read-only MCP does not offer these approval tools;
  `--cloud-auth browser --read-only` is rejected rather than becoming local mode.
- In browser mode, use `cloud_lock` with a non-secret reason to end access.
  Restart, 2 hours idle, or 12 hours total also ends access by default; pending
  approval expires in 10 minutes. `--cloud-idle-timeout` and
  `--cloud-session-max-age` customize positive durations up to 30 days each;
  an earlier device-token expiry still applies.
  Existing admitted operations may finish after locking. Each new connection
  checks remote authorization and a signed snapshot, with no offline fallback.
- Browser approval grants this whole MCP process full vault credential access
  under its existing AI command authority; it is not approval for just one host
  or command. Credentials and the temporary device token stay in process memory.
  This does not prevent same-user process inspection or authorized remote commands
  from reading remote secrets; do not promise arbitrary command output is secret-free.
- In browser mode, missing or ambiguous cloud credentials, encrypted private keys, conflicts,
  unsupported device terminals or unsupported routes require correction outside
  chat. Do not fall back to local keys or agents for a cloud binding. Only simple
  vault-owned ProxyJump routes are supported; no nested jumps, external
  ProxyCommand, forwarding or SOCKS routes.
- `cloud register/login --username <name> --import-local` encrypts locally and
  merges existing records. Original configuration remains intact.
- `cloud presence` reports online status only. It does not authorize remote Shell.
- `cloud watch` holds an unlocked vault in its process and syncs periodically.
- `cloud conflicts` preserves conflicting records. Do not choose credentials or
  delete same-name records based only on alias; retain different users/routes.
- `sshm update --check` verifies the signed release feed. Installing an update
  needs explicit user intent or the CLI confirmation; do not set `--yes` merely
  to bypass the question. Existing signed updates may refresh only SSHM-managed
  integrations. Plugin-managed or locally edited skill files stay untouched.
- `sshm integrations status` inspects setup. Use `integrations install --app
  codex|claude|all` only when requested. MCP registration is a separate `--mcp`
  option, using each app's own CLI; never replace another server configuration.
