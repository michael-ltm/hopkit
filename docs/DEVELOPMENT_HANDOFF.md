# SSHM development handoff — 2026-09-08

SSHM manages local SSH connections and optional client-encrypted cloud synchronization. Production endpoint: https://sshm.yunmini.net. Latest client release target: `0.8.0-cloud-preview.32`. See `docs/2026-09-08-device-version-reporting.md` for deployment evidence and `docs/cloud-sync.md` for architecture.

## Start here

- CLI / interactive home: `internal/commands/root.go`, `home.go`, `internal/ui/home.go`.
- Encrypted vault, synchronization and merge: `internal/cloudsync/`.
- Outbound encrypted terminals: `internal/cloudagent/`, `internal/cloudsync/shell_client.go`.
- Cloudflare account service / relay / jobs: `cloud/src/index.ts`, `relay.ts`, `jobs.ts`.
- Web UI: `cloud/src/browser/`, `cloud/src/page.ts`, `cloud/src/style.ts`.
- Platform inventory: `internal/inventory/`.
- Signed updates / integration documents: `internal/updater/`, `internal/integrations/`, `plugins/sshm-skill/`.

## Local checks

Go requirement is declared in `go.mod`. Run `go test ./...` and `go vet ./...`. Live integration tests are opt-in and must use disposable accounts/targets. A plain source build currently defaults to `0.7.0`; pass an explicit `internal/commands.Version` linker value for versioned development builds. Do not confuse the default with the deployed release.

Cloud: install dependencies using the committed pnpm lockfile, then `pnpm --dir cloud check` and `pnpm --dir cloud test`.

Important fresh-clone boundary: `cloud/public/downloads/` is deliberately ignored. The browser build currently also validates installers against the signed release and all six exact executable assets. Therefore Cloud checks require those local release assets; a clean clone alone is insufficient for that step. Obtain a complete matching signed release through the trusted release workflow. Do not bypass checks or put the signing private key in Git. Generated browser and terminal bundles are also ignored and regenerated. Node modules, Wrangler local databases, account state and credentials are not repository contents.

Release scripts: `scripts/build-cloud-clients.py`, `scripts/sign-cloud-release/`. Rebuilding a published version can produce different bytes; do not overwrite an existing published release with newly rebuilt binaries. Use a new release version and authorized signing environment. Pushing main runs CI; it does not deploy Cloudflare or publish a release tag by itself.

## Runtime distinctions and pending operational work

- Installed file, running MCP process, running cloud agent, and last heartbeat are distinct. Version `.30` records installation observations separately from legacy process heartbeats.
- MacBook Air / Mac mini / GrokBot were updated to `.30`. Existing older agents were not forcibly interrupted. Restarting an agent may need local unlock or approved device linking; do not copy its in-memory vault key.
- `tmp-ai-compute` was offline at final version-display acceptance. Its last `.25` heartbeat is historical, not proof of installed version or a completed update.
- Continuous terminals use protocol v3 with short admission authorization; old protocol requests retain their original lifetime. Existing agents must actually load the new binary.
- A previous old MCP process dropped unknown cloud binding fields while writing activity. Compatibility sidecars and authenticated sync recovery were implemented in `.27–.29`. The user's local binding recovery still requires an unlocked sync unless verified separately; do not guess identities or report it completed from this document.
- Plugin-managed Codex / Claude skills are preserved by the updater; update their owning plugin through its supported mechanism. Never silently rewrite plugin caches.

## Execution environment

See `docs/execution-environment.md` for login-shell/PATH handling and `sshm doctor` / MCP `check_environment`. Missing CLI discovery or unavailable credentials in an SSH session must never be described as proof that the desktop user has not logged in. Preview.32 adds the opt-in same-user desktop agent described in `docs/desktop-session.md`; it resolves the Mac mini keychain session difference.

## Safe continuation

Use a fresh installed MCP process for real SSHM operations and check its runtime version. Preserve known-host verification and credentials. Never include local config, account tokens, vault phrases, API keys, recovery material or signing private keys in commits, logs or handoff documents. Keep test evidence explicit: local unit tests, simulated services, and real targets are different.

The separate `connector-hub` project uses SSHM as a reference, not as its working directory. It must have its own accounts, cryptographic context labels, storage namespaces and domain. Do not point its test writes at SSHM production.
