# SSHM development handoff — 2026-09-28

SSHM manages local SSH connections and optional client-encrypted cloud synchronization. Production endpoint: https://sshm.yunmini.net. Published cloud client release: `0.8.0-cloud-preview.35`. See [the September 27 release report](superpowers/reports/2026-09-27-preview35-release.md) for current deployment evidence and `docs/cloud-sync.md` for architecture. The older `docs/2026-09-08-device-version-reporting.md` records the previous rollout.

## Start here

The September 28 website update makes local installation the primary path. Cloud enrollment, credential migration and AI integration are optional expandable instructions. Remote tasks and web terminal guidance remain under advanced controls. Browser vault unlocking still protects cloud contents; it does not lock the device's saved local credentials. See [the website update report](superpowers/reports/2026-09-28-local-first-website.md).

- CLI / interactive home: `internal/commands/root.go`, `home.go`, `internal/ui/home.go`.
- Encrypted vault, synchronization and merge: `internal/cloudsync/`.
- Outbound encrypted terminals: `internal/cloudagent/`, `internal/cloudsync/shell_client.go`.
- Cloudflare account service / relay / jobs: `cloud/src/index.ts`, `relay.ts`, `jobs.ts`.
- Web UI: `cloud/src/browser/`, `cloud/src/page.ts`, `cloud/src/style.ts`.
- Platform inventory: `internal/inventory/`.
- Signed updates / integration documents: `internal/updater/`, `internal/integrations/`, `plugins/sshm-skill/`.

## Local checks

Go requirement is declared in `go.mod`. Run `go test ./...` and `go vet ./...`. Live integration tests are opt-in and must use disposable accounts/targets. A plain source build currently defaults to `0.7.1`; pass an explicit `internal/commands.Version` linker value for versioned development builds. Do not confuse the default with the deployed release.

Cloud: install dependencies using the committed pnpm lockfile, then `pnpm --dir cloud check` and `pnpm --dir cloud test`.

Run `pnpm --dir cloud test:ui` for the unlock dialog and terminal eligibility regressions in headless Chromium. It uses a temporary Go-generated encrypted vault and local HTTP fixtures, with no real account or SSH target. Go and Chromium are required; set `CHROMIUM` if the executable is not `/usr/bin/chromium`.

Important fresh-clone boundary: `cloud/public/downloads/` is deliberately ignored. The browser build currently also validates installers against the signed release and all six exact executable assets. Therefore Cloud checks require those local release assets; a clean clone alone is insufficient for that step. Obtain a complete matching signed release through the trusted release workflow. Do not bypass checks or put the signing private key in Git. Generated browser and terminal bundles are also ignored and regenerated. Node modules, Wrangler local databases, account state and credentials are not repository contents.

Release scripts: `scripts/build-cloud-clients.py`, `scripts/sign-cloud-release/`. Rebuilding a published version can produce different bytes; do not overwrite an existing published release with newly rebuilt binaries. Use a new release version and authorized signing environment. Pushing main runs CI; it does not deploy Cloudflare or publish a release tag by itself.

The release builder requires `--version` and `--darwin-dir`. Build both Darwin architectures on macOS from the same source revision with `CGO_ENABLED=1` to retain the native reader for existing `keychain:` items. New `keychain-host:` items use the stable Apple-signed `/usr/bin/osascript` host with fixed embedded JavaScript and Security.framework; replacing the SSHM executable therefore preserves its Keychain caller identity without broader ACL grants. Omit `-trimpath` for these two builds: the staging validator reads the embedded linker assignment as well as `GOOS`, `GOARCH`, and `CGO_ENABLED` from `go version -m -json`.

```sh
# On macOS, from the intended release source revision; choose a new version.
release_version=0.8.0-cloud-preview.35
darwin_build_dir=/tmp/sshm-native-$release_version
mkdir -p "$darwin_build_dir"
for arch in amd64 arm64; do
  MACOSX_DEPLOYMENT_TARGET=12.0 CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" go build \
    -ldflags "-s -w -X github.com/michael-ltm/sshm/internal/commands.Version=$release_version" \
    -o "$darwin_build_dir/sshm-darwin-$arch" ./cmd/sshm
done

# Transfer only those two binaries to the release workstation, then stage all six.
python3 scripts/build-cloud-clients.py --version "$release_version" \
  --darwin-dir /path/to/native-binaries --output /path/to/new-staging-directory
```

Without `--output`, staging uses `dist/releases/<version>`. Existing output directories are rejected, and `cloud/public/downloads` remains untouched. The builder validates both copied Darwin binaries before building Linux/Windows with `CGO_ENABLED=0`, then writes `SHA256SUMS`. Sign the complete staged directory with `go run ./scripts/sign-cloud-release --version <version> --assets <staging-directory> --key <existing-private-key-path>` in the authorized signing environment before preparing public downloads and deploying. Run the staging safety tests with `python3 -B -m unittest discover -s scripts -p 'test_build_cloud_clients.py'`.

After validating the complete public assets and generated installers, deploy with `pnpm --dir cloud run deploy`. The explicit `run` is necessary: bare `pnpm deploy` selects pnpm's workspace deployment command. The older tag-triggered GoReleaser workflow still builds Darwin with CGO disabled; do not use that workflow for this native-Keychain-compatible cloud release.

## Runtime distinctions and pending operational work

- Installed file, running MCP process, running cloud agent, and last heartbeat are distinct. Version `.30` records installation observations separately from legacy process heartbeats.
- MacBook Air, Mac mini, GrokBot and the local Linux workstation now have `.35`; executable hashes match the signed release. Fresh MCP initialization on each remote host reports `.35`. The local service and Mac mini desktop helper were restarted. Existing AI sessions and cloud agents retain their loaded process until restarted; do not copy in-memory vault keys.
- `tmp-ai-compute` was offline at final version-display acceptance. Its last `.25` heartbeat is historical, not proof of installed version or a completed update.
- Continuous terminals use protocol v3 with short admission authorization; old protocol requests retain their original lifetime. Existing agents must actually load the new binary.
- A previous old MCP process dropped unknown cloud binding fields while writing activity. Compatibility sidecars and authenticated sync recovery were implemented in `.27–.29`. The September 27 recovery separately verified persistent local credentials for `prod-go`, `grokbot`, `aliyun-hcg-prod` and `racing-server`, with an unavailable external Agent. This does not establish recovery for every historical cloud entry.
- Plugin-managed Codex / Claude skills are preserved by the updater; update their owning plugin through its supported mechanism. Never silently rewrite plugin caches. Installed SSHM plugins on the three remote machines now use the current `0.7.1` plugin assets; this version is independent of the `.35` executable. Existing enabled/disabled states were preserved. Restart Claude or open a new Codex thread to load the updated integration.

## Execution environment

See `docs/execution-environment.md` for login-shell/PATH handling and `sshm doctor` / MCP `check_environment`. Missing CLI discovery or unavailable credentials in an SSH session must never be described as proof that the desktop user has not logged in. Preview.33 adds the opt-in same-user GitHub credential bridge described in `docs/desktop-session.md`; it resolves the Mac mini keychain session difference while keeping filesystem access in SSH.

## Safe continuation

Use a fresh installed MCP process for real SSHM operations and check its runtime version. Preserve known-host verification and credentials. Never include local config, account tokens, vault phrases, API keys, recovery material or signing private keys in commits, logs or handoff documents. Keep test evidence explicit: local unit tests, simulated services, and real targets are different.

The separate `connector-hub` project uses SSHM as a reference, not as its working directory. It must have its own accounts, cryptographic context labels, storage namespaces and domain. Do not point its test writes at SSHM production.
