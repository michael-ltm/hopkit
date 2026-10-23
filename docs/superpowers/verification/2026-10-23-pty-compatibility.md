# PTY compatibility verification — 2026-10-23

Source baseline: `22976438c5ef42911d322192b12fb9aef05601df`.
Implements the findings in the ai-client worktree report
`docs/superpowers/verification/2026-10-23-sshm-pty-compatibility.md`.

## Changes

- Shared `SessionError` preserves original causes and identifies session open,
  terminal size, local TTY, PTY request, stdin pipe, shell start and command start.
  Only the exact x/crypto rejection maps to `pty_denied`; EOF, cancellation and
  deadlines remain distinct. Dial failure categories and activity semantics are unchanged.
- CLI connect adds explicit `sshm exec <alias> --raw-environment <command>`
  guidance only after confirmed PTY denial. There is no automatic shell/exec fallback.
- Interactive setup starts reading local input only after Shell/Start succeeds.
  Terminal/Unix pipe reads are cancelled on exit; TTY state is restored on errors.
  Windows redirected input retains its original reader because cancelreader opens CONIN$.
- Cloud errors retain the legacy `pty_unavailable` wire value and add optional,
  allowlisted `diagnostics`. The browser distinguishes PTY, session and shell failures.
  No raw cause, host, credential or command is included in diagnostics.
- Loopback regression tests additionally found that raw CLI/MCP execution could
  issue automatic installation/platform probes when metadata expired. Raw mode
  now sets `SkipDiscovery`, so only the requested command is sent. Normal exec
  continues to prepare its environment.

## Verification

Observed red tests before fixes: missing connect guidance and session stages,
context cancellation returning only EOF, additional exec requests in raw mode,
and cloud failures lacking distinct diagnostics.

Final checks passed:

- `GOCACHE=/tmp/sshm-pty-gocache GOPROXY=off GOSUMDB=off go test -count=1 ./...`
- `go test -race ./internal/ssh ./internal/cloudagent ./internal/commands ./internal/mcp`
  with the same cache/offline settings; new Linux TTY/input tests were also run under race.
- `pnpm check` in `cloud`.
- `pnpm test` in `cloud`: 27 Node tests and 18 Vitest tests passed. The first
  Vitest run could not write its default Wrangler log under the sandbox; rerunning
  with `WRANGLER_LOG_PATH=/tmp/sshm-pty-verification/wrangler.log` passed cleanly.
- Windows amd64 cross-build succeeded. Native Windows execution was not performed.
- `git diff --check` and independent code review passed.

New integration fixtures use generated test keys, pinned known_hosts and loopback
servers. They verify request order/count, no fallback, cancellation, remote exit
64, input/output/resize, sensitive command PTY denial, local TTY restoration,
raw command quoting/spacing/`--`, and encrypted relay diagnostics with legacy
payload compatibility.

## Local installation and inventory

Installed `/home/ming/.local/bin/sshm` as `0.8.0-cloud-preview.37+pty.1`.
Installed and built binary SHA-256:
`8766e3b1ac31ba83175794fb0418cd6e39e1c0630573f773f234af8e3e954d8f`.

Per user request, removed the old root alias `deepsearix` using MCP, then renamed
`deepsearix-view` to `deepsearix` through config.Update and appended an audit entry.
Verified the new entry exactly preserved the original view configuration before
live checks. Default/project references were unchanged. Another server's activity
timestamps advanced concurrently; its connection configuration was unchanged.

Live checks:

- MCP `get_server(deepsearix)` resolves to `cs-hub-view`; `deepsearix-view` is absent.
- `check_ssh(mode=exec)` authenticated successfully (`ssh.ok=true`); its hostname
  probe was rejected with exit 64 by the existing whitelist (`exec.ok=false`).
- Installed CLI `connect deepsearix` returns exit 1 with the original PTY rejection
  and the new explicit-exec guidance.
- Installed CLI and MCP `docker ps` in raw mode return exit 0; API is healthy.

The account continues to allow only the server-approved container diagnostics.
The patch does not grant an interactive shell. Cloud browser changes are in source
and have not been published. Existing MCP/agent processes keep their loaded version
until restarted; new CLI invocations use the installed patch.

Temporary rollback artifacts (private config file permissions are 0600):

- `/tmp/sshm-pty-verification/config-before-alias-change.toml`
- `/tmp/sshm-pty-verification/sshm-before-pty-fix`
- `/tmp/sshm-pty-verification/go-test.log`

The user subsequently authorized committing/pushing this fix and updating both
the local Linux installation and Mac mini. Native Mac verification and installation
are recorded separately after deployment.
