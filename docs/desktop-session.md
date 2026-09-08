# macOS desktop session execution

SSHM preview.32 fixes an observed macOS authorization difference: the same `gh` executable and existing `michael-ltm` login failed from sshd's Background security session, while an independent launchd job in the same OS user's GUI session successfully accessed GitHub. Preview.31's login-shell/PATH fix alone could not resolve this. No new GitHub login or token replacement is required for this case.

## Enable and inspect

On the Mac which already has a desktop login:

```sh
sshm desktop enable
sshm desktop status
```

Enable installs `~/Library/LaunchAgents/net.yunmini.sshm.desktop.plist` for that OS user and opts their SSHM user commands into desktop execution. The service requires an existing `gui/<uid>` session and refuses to run as a Background-session impostor. It runs the installed SSHM executable, survives normal command exits, and starts with subsequent desktop logins. Other users' GUI sessions are never selected. The daemon's reported version is the loaded version, distinct from a newly updated executable on disk.

After enabling, CLI `sshm exec`, MCP `exec` / `exec_multi` and project execution automatically use the desktop session on that Mac. `sshm doctor <alias>` and MCP `check_environment` report `execution_context: desktop_user`. This still uses the owning user's noninteractive login shell and keeps common PATH resolution. Linux and Windows keep their native execution paths; `desktop enable` there returns an explicit unsupported-platform error.

For service control from another device, retain the raw SSH environment:

```sh
sshm exec --raw-environment mac-alias 'sshm desktop status'
```

If the raw PATH does not contain SSHM, use its known absolute installation path. An enabled but unavailable service fails before command submission. Lost transport after submission has an unknown outcome; SSHM never reruns that command in another environment. Use the original environment explicitly for operations which should not use desktop credentials.

## Credential and process boundaries

- The service uses a private Unix socket under `/tmp/sshm-desktop-<uid>` (directory 0700, socket 0600), validates ownership and rejects symlinks. Both sides verify the peer's OS UID. There is no TCP listener or web endpoint.
- Only commands, working directories and streamed results cross this local channel. Tokens, passwords and keychain unlock phrases are neither exported nor saved by the service. It does not change keychain ACLs, reset GitHub login, unlock the keychain or relax macOS security settings. The user's existing applications continue using their usual OS credential storage.
- Commands and their output are not written to temporary files or service logs. Existing SSHM MCP command auditing and output masking still apply at the caller.
- Requests are bounded, concurrent connections are limited, and malformed requests are rejected before executing. A disconnected client cancels its command's process group. Stream contents and exit codes are preserved.
- This is an intentional grant to processes running as this OS user, including authorized SSHM automation, to execute in that user's desktop session. A logged-out desktop or locked/restricted keychain can still prevent an application from accessing its credentials; no bypass is attempted.
- `sshm desktop disable` explicitly stops the service, including its active commands, and removes its enable marker and LaunchAgent. Updates do not automatically kill running commands or replace a running process's loaded code.

## Git helper is a separate setting

Once `gh api user --jq .login` succeeds, HTTPS Git also needs an appropriate credential helper. On Mac mini the GitHub-specific helper was absent and was configured using `gh auth setup-git --hostname github.com`. No credential bytes were copied into Git configuration. Keep existing helper configurations when present and test the actual repository operation; API access alone is not proof of Git access.

References: [GitHub CLI macOS keyring implementation](https://github.com/cli/cli/blob/trunk/docs/macos-keyring.md), [GitHub CLI supported Git setup](https://cli.github.com/manual/gh_auth_setup-git).
