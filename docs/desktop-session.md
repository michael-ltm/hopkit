# macOS GitHub credential bridge

Preview.33 resolves two independently verified macOS session boundaries:

1. The existing `gh` login works in the owning user's GUI session, but keychain lookup fails from sshd's Background session.
2. Moving complete Git commands into a standalone GUI agent can block reads of repositories in protected Documents folders. Git and filesystem work must retain the already-authorized SSH context.

SSHM therefore delegates **only GitHub credential lookup** to a same-user desktop agent. Git, the real GitHub CLI, Node, Python and repository operations execute in the original SSH context. No new GitHub login, keychain ACL change or extra Documents permission is needed for the verified Mac mini case.

## Enable and inspect

On the Mac which already has a desktop login and GitHub CLI:

```sh
sshm desktop enable
sshm desktop status
```

This installs a same-user LaunchAgent and a private `gh` shim under `~/Library/Application Support/sshm/desktop/bin`. SSHM's user-command environment prepends that directory and adds process-local GitHub credential-helper settings. Existing Git settings are retained; the bridge is scoped to HTTPS `github.com`. Shell/Git configuration files are not rewritten by this PATH/helper setup.

`sshm doctor <alias>` and MCP `check_environment` report execution and credential contexts separately: file execution remains `remote_ssh`, while `github_credential_context: desktop_user` identifies delegated authorization. GitHub authorization must still be verified by the actual API or repository operation.

The shim resolves the native `gh` executable separately to avoid recursion. Explicit `GH_TOKEN`/`GITHUB_TOKEN` values take precedence. Custom GitHub config directories and enterprise selections use their own native credentials. Help/version commands do not request credentials. Changing GitHub logins remains an explicit operation in the user's desktop terminal.

Linux and Windows retain their native execution paths. Enabling this macOS-specific service there returns an explicit unsupported-platform error.

## Credential and process boundaries

- The private Unix socket uses a 0700 directory and 0600 socket. Both sides verify the peer's OS UID and validate endpoint ownership; symlinks and unsafe permissions are rejected. There is no TCP or web listener.
- The service can run only in the owning user's existing Aqua/GUI session. It never selects another user, uses sudo, unlocks a keychain or changes OS privacy settings.
- The existing GitHub credential travels in memory over the private local socket to the short-lived native `gh` child. It is supplied in that child's environment, never a command-line argument, persistent file, service log, shared shell environment or ordinary MCP result. Git's requested credential response travels directly to Git. Arbitrary Node/Python/shell commands do not inherit a newly injected token.
- The agent stores executable paths and enable state only. It neither creates a token vault nor uploads credentials to SSHM Cloud. The user can still deliberately request their own credential using native `gh` commands; AI callers must never print tokens.
- Existing SSHM auditing and masking remain at the caller. IPC requests and responses are bounded, commands stream output with exit codes preserved, and disconnects cancel the request's process group. A lost response is an unknown outcome and never triggers automatic replay.
- A logged-out desktop or locked/restricted keychain can prevent lookup; unavailable access is not proof of a logged-out GitHub account.

`sshm desktop disable` removes the enable marker and LaunchAgent and explicitly stops that service's active requests. Running services retain their loaded version after a binary update; they should be restarted only when their active work has finished.

The advanced `sshm desktop exec -- '<command>'` still explicitly runs a complete command in the GUI context. It is not the default routing path and is subject to that context's Documents/privacy permissions. Use `sshm exec --raw-environment` when inspecting/restoring a remote service without environment augmentation.

## Verification

Cover API identity, actual private Git fetch, readable repository files, native program lookup, socket ownership, disconnect cancellation, host-bound helper requests, caller-credential precedence and failure without replay. A successful `gh api` check alone is not proof that Git can access the repository.

References: [GitHub CLI macOS keyring implementation](https://github.com/cli/cli/blob/trunk/docs/macos-keyring.md), [GitHub CLI credential setup](https://cli.github.com/manual/gh_auth_setup-git), [GitHub CLI environment precedence](https://cli.github.com/manual/gh_help_environment).
