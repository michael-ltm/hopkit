# Execution environments and authorization

`sshm exec`, MCP `exec`, `exec_multi` and project commands now resolve programs in the authenticated user's noninteractive login environment. This fixes commands such as Homebrew `gh` / Node / Python being present in a desktop terminal but absent from sshd's minimal PATH.

- macOS and Linux: a detected POSIX-compatible shell runs with `-lc`. Its login profile's exported variables and PATH apply. Missing conventional Homebrew, Linuxbrew, user bin, pyenv/asdf/mise shims, Volta and MacPorts directories are appended; existing selection wins. If Node remains absent, an existing user-owned nvm initialization script may select its configured default. fnm and other custom managers should export their selection from the login profile. SSHM does not guess the newest installed version or alias `python` to `python3`.
- Windows: detected CMD, Windows PowerShell and PowerShell Core retain their shell family. Each child process refreshes missing PATH entries from that user's and the machine's registry PATH plus WinGet/npm locations. Existing process entries retain precedence, including paths with spaces. This does not change registry values or restart sshd. Other registry environment variables and credentials are not imported.
- Unknown shells retain the original environment. Interactive-only aliases, functions and environments selected inside a different terminal are not guaranteed to exist in noninteractive sessions. Login startup files can have side effects or write output; keep terminal-only setup behind an interactive check.
- `sshm exec --raw-environment alias 'command'`, or MCP `raw_environment: true`, retains the original sshd environment. This option is for foreground direct SSH commands; it is rejected for detached/cloud-reference CLI execution rather than silently ignored. Internal SSH protocol probes still use raw execution.
- Cloud terminal sessions already start an interactive login shell. This change does not transfer the desktop session's secrets to a cloud agent or restart active terminals.

## Diagnose before asking someone to log in again

```sh
sshm doctor                    # current local process
sshm doctor elons-mac-mini      # target SSH session
```

AI clients can use `check_environment` with an optional `alias` and required `reason`. It reports CLI paths for gh/git/Node/npm/Python, the OS user, execution scope and a read-only GitHub API check. It never prints tokens or runs login/logout. `verified` includes the verified account; `unavailable_in_session` means this session could not authorize the request; `cli_not_found` means the executable was not found. None of these failure states proves that another terminal is logged out. A GitHub API check is not a claim that a private repository's Git credential helper is configured or that every repository scope is granted.

Check the OS user, PATH, login profile, selected account, session/keychain access, network and Git credential-helper wiring separately. macOS keychain access in an SSH session can differ from access in the user's desktop terminal. Never export a token to a plaintext file, copy it between machines or weaken keychain protection to make a probe pass.

References: [Bash startup behavior](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html), [Windows OpenSSH shell configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration), [GitHub CLI credential storage](https://cli.github.com/manual/gh_auth_login), [GitHub CLI environment selection](https://cli.github.com/manual/gh_help_environment).
