# PTY fix rollout — 2026-10-23

Final installed source commit: `cce524c9ebb27231c35f32a2d9d5777d78480302`, pushed to
`https://github.com/michael-ltm/sshm.git` on `main` at the user's request.
Both installations report `0.8.0-cloud-preview.37+pty.1` and embed that clean source
revision (`vcs.modified=false`). This is a local patch build, not a new public release.

| Evidence | Local Linux | Mac mini (`elons-mac-mini`) |
| --- | --- | --- |
| Workspace | `/home/ming/Documents/code/my/sshm` | `/Users/elonjack/Documents/code/project/my/sshm` |
| Installed artifact | `/home/ming/.local/bin/sshm` | `/opt/homebrew/bin/sshm` |
| Architecture | linux/amd64 | darwin/arm64 |
| Bytes | 14991623 | 13524898 |
| Previous version | `.37+pty.1` from the verified dirty workspace | `.37` |
| Build/install | Rebuilt from committed source and atomically replaced | Native CGO=1, macOS 12 deployment target; atomically replaced after tests |
| CLI version smoke | passed | passed |
| Fresh MCP initialize | `.37+pty.1` | `.37+pty.1` |
| Background process | Existing local credential service restarted at 14:35:25 UTC; systemd reports active with the canonical installed path | Existing `net.yunmini.sshm.desktop` LaunchAgent restarted; `state=running`, exit code 0 |

SHA-256:

- Linux: `da6e41134b97f72472351261a05cec246fbced9e5ed0449404809abd55e6cf57`
- macOS: `1a0a5ce58a42b11f6bd1c8245a6a167445410bb07ba840eff5fd0da2aab0743e`

The final Mac build began at `2026-10-23T14:34:34.800886Z`; installation and
LaunchAgent readiness were verified at `2026-10-23T14:36:06.086156Z`.
Before the first installation, the existing file was 13491858
bytes with SHA-256 `b45081db2bfed5f46d031ad145dea5440ce704935427ee8af295985f26f85159`.
The candidate's creation time, clean source metadata, version, nonzero size,
code signature and checksum were checked before promotion. The existing
`~/.local/bin/sshm` symlink still resolves to the canonical Homebrew-bin path.

Checks passed:

- Linux: fresh `go test -race -count=1 ./...` and `go vet ./...` at `cce524c`.
  Browser Node tests (27), Vitest tests (18), and `pnpm check` passed at `a038e0e`;
  browser code is unchanged in the follow-up.
- Mac mini: native `CGO_ENABLED=1 go test -count=1 ./...` and `go vet ./...`.
  The affected SSH/keystore packages also passed native `go test -race -count=1`
  at `cce524c`, followed by full `go vet ./...`.
  Existing legacy Keychain API deprecation warnings remain; tests and build succeeded.
- Local live `sshm exec deepsearix --raw-environment docker ps` after service restart
  returned exit 0; the API container reported healthy.
- Final installed `sshm connect deepsearix` returned the confirmed PTY-denial
  diagnostic and raw-exec hint. The alias resolves to `cs-hub-view`;
  `deepsearix-view` is absent.

The initial GitHub [CI run](https://github.com/michael-ltm/sshm/actions/runs/39968618850)
passed Linux and Windows but exposed two macOS tests that assumed an isolated
HOME also disabled launchd Agent discovery. The runner's reachable Agent caused
the expected fallback/error conditions not to occur. Commit `cce524c` isolates the
unavailable-agent fixture's candidate paths and tests the managed Go Agent's
lifecycle through its own socket. Normal platform discovery is unchanged.

Follow-up [CI run](https://github.com/michael-ltm/sshm/actions/runs/39970754571):
completed successfully. Linux, macOS and Windows `go vet` and full `go test -race`
jobs passed. The integration job also passed; its SSHD test step still has the
repository's existing skip-on-failure placeholder, so that step is not evidence of
a complete SSHD integration test. The synthetic SSH fixtures and live restricted
account checks above supply the relevant PTY/raw-exec evidence.

Rollback/evidence:

- Linux original `.37` binary and config: `/tmp/sshm-pty-verification/`.
  `sshm-before-committed-build` additionally preserves the preceding workspace build.
- Linux final update: `sshm-before-cce524c` and `installed-cce524c.json` in the same
  directory. Direct inspection of the running credential service's `/proc/.../exe`
  was denied; installed-file checksums and systemd restart/path/status were verified.
- Mac mini: `dist/pty-compat-a038e0e/` and `dist/pty-compat-cce524c/` under its verified workspace contain
  `sshm-before-update`, `prebuild.json`, `installed.json`, `go-test.log`, and `go-vet.log`.

Existing AI-owned MCP sessions were preserved; they load the new executable on
reconnection. Fresh MCP processes were verified on both machines. The Mac's
credential-service migration was not part of this update. No cloud release or
website deployment was performed.

## Recognition in future connections

The client automatically distinguishes a confirmed PTY denial from authentication,
transport, timeout, cancellation, session-open and shell-start failures. Confirmed
PTY denial produces an explicit raw-exec hint; permitted commands still come from
the server's verified whitelist. There is no automatic shell fallback, arbitrary
probe replay or server-permission change. A failed `hostname` probe with
`ssh.ok=true` and `exec.ok=false` remains an authenticated connection whose command
was refused, not an authentication failure.
