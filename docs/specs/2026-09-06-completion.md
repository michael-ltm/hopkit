# SSHM completion and console density

User authorized completing the outstanding cloud enrollment/merge, local-key
migration and browser terminal, plus a full console layout review. Browser QA
uses the already logged-in claude-browser profile gumusbierre99. No real secret
is read into tool output. The existing account is z13035341; its browser vault
is currently locked and will need one user-owned unlock for real approvals.

## Implementation

- Compact responsive tables, constrained descriptions/tags, pagination, filter
  empty states, bulk group/tag editing through one encrypted CAS update, and
  consistent settings/forms/navigation. Keep existing account/vault protocol.
- Browser-approved enrollment: each CLI creates an ephemeral P-256 key and a
  separate high-entropy poll secret. The browser displays a fingerprint derived
  from the target key, requires the unlocked vault and signs approval with the
  vault root. It encrypts the master key to that ephemeral target. Poll secrets,
  account tokens and master keys never appear in logs. Requests expire after
  ten minutes; retry responses are idempotent until acknowledgement/expiry.
- Enrolled clients import their own inventory/credentials in memory and use
  existing three-way encrypted CAS sync. Preserve different users, keys and
  routes; never overwrite local inventories as a side effect of cloud merge.
- Key migration: verify and upload an encrypted recovery backup before changing
  a configured private key or removing its adjacent recovery sidecar. Keep the
  public identity unchanged, add/prove signing through ssh-agent, atomically
  replace plaintext keys with passphrase-encrypted files. Retain any item that
  cannot be proven recoverable. Do not archive plaintext backups alongside keys.
- Browser shell: explicit local agent opt-in, outbound WSS only, account-scoped
  relay, root-signed short-lived session authorization checked by both relay and
  agent, per-session AES-GCM keys derived from the unlocked master, strict
  sequence/direction binding, no transcript persistence. Browser lock/close,
  revocation, agent shutdown and expiry close the PTY. Native PTY on Unix and
  ConPTY on Windows; bundled xterm renderer with no clipboard integration.
- Agent master key stays in memory, never in a configuration file. After an
  agent restart it must be unlocked/approved again. Session tokens alone cannot
  authorize a browser shell or decrypt the vault. Existing AI connections use
  their local SSH agent independently.

## Acceptance

Go tests/vet, Workers tests for unauthorized/replayed/revoked/expired grants and
sessions, crypto interoperability and tampering tests, cross-platform build and
native Windows tests. Browser functional/layout QA uses synthetic test records,
then readback of the real account after a manual vault unlock. Finally deploy,
upgrade the four authorized machines, execute a harmless shell marker through
the web terminal, compare imported inventories and key fingerprints, and report
any unrecoverable key separately without deleting it.

## Verified delivery, 2026-09-06

- Reference inspected live: the user's Tailscale Machines console. Final web
  layout uses a white workspace, warm gray navigation, 60 px inventory rows,
  fixed table headings, restrained tags and keyboard-accessible row menus.
- Browser acceptance in gumusbierre99: 55 synthetic connections, 25-row bulk
  grouping/tag append, pagination, empty search, 390 px responsive layout,
  on-screen menus/forms, browser-to-Go approval, and an encrypted native shell
  executing a composed success marker. Go readback confirmed all 55 synthetic
  passwords unchanged after browser edits. Synthetic account deleted afterward.
- Native encrypted PTY process tests passed on macOS, GrokBot Linux and att-dev
  Windows ConPTY. Go tests, race checks for cloudsync/cloudagent, vet, six-target
  builds and six Workers tests passed. Production API round-trip covered keys,
  passwords, real fixture SSH logins, merge/retry, isolation, rotation/recovery
  and revocation.
- Current signed release: 0.8.0-cloud-preview.10. Worker deployment:
  013e13ce-ca66-465d-9599-47301f1ff556. Production UI readback confirmed new layout
  and the existing authenticated account; real vault remained locked.
- Local automatic Update/Skip checks and the real signed upgrade to preview.10
  passed using isolated terminal fixtures. Local, Mac mini and GrokBot upgraded;
  inventories remained 37, 31 and 8 respectively. Existing plugin-manager-owned
  integrations were retained, not rewritten by the client updater.
- Pending user-owned vault unlock: real enrollment, encrypted inventory merge,
  key migration and real-device web-shell acceptance. Three approval requests
  were started with private status files and ten-minute expiry; if expired they
  must be restarted, never bypassed. No real key was migrated while locked.
- att-dev became unreachable on SSH after its successful native PTY test.
  Rechecks from the local machine and Mac mini both timed out. Its upgrade and
  enrollment remain pending reachability; no network settings were changed.


## Follow-up: colored OS icons, observations, installation status (preview.13)

- Published signed darwin/linux/windows amd64/arm64 clients, version
  `0.8.0-cloud-preview.13`; Cloudflare Worker deployment
  `f5151a4f-fa86-4f34-8dca-769b4c29b2af`.
- Local, Mac mini and GrokBot updated. Mac mini and GrokBot config files remained
  byte-for-byte identical across update (31 and 8 entries); local retained all
  37 aliases and every existing field. The additive observation fields account
  for differences in old/new CLI JSON schema.
- Actual local scan: 37 targets, 2 detected SSHM installations, 10 absent from
  PATH/common locations, 25 unconfirmed. Failed or unconfirmed targets remain.
  The first scan exposed jump-host usage tracking; after adding ProbeOnly the
  repeat scan left every target's LastUsed unchanged. No historical timestamp
  rollback was attempted without a trustworthy before snapshot.
- Authenticated OS/version checks support POSIX and Windows PowerShell. These
  probes do not require SSHM preinstalled on the target. The installation scan
  is scoped to PATH and common install locations, not a complete disk search.
- Browser colors verified against a synthetic 56-entry vault: latest release
  green, older version orange, missing red, unavailable/unchecked gray. OS SVGs
  have distinct colors and do not require icon fonts. Authentication failure
  with zero successful connection history was visible and retained.
- Browser decrypted new signed revisions without a second unlock. Desktop rows
  remain 60px. At a 390px viewport the body stays 375px; the wider data table
  scrolls inside its container. Synthetic screenshots are stored under
  `dist/cloud-preview/web-color-activity-{desktop,mobile}.png` (ignored artifacts).
- Actual background behavior verified: vault remained unlocked during the
  grace period and locked after one minute; Shell still closes immediately.
- Go package tests, vet, affected race tests, TypeScript/browser build, backend
  tests and production synthetic cloud integration passed. Real Update/Skip
  checks upgraded a separate fixture from preview.11 to preview.13, preserved
  its config, and left its binary unchanged when skipped.
- att-dev remained unreachable on SSH port 22. Its installed runtime has not
  been upgraded from preview.8 and this does not prove SSHM is absent.
- Real account device approval and historical-key migration are separate from
  the above synthetic acceptance: fresh requests are waiting on a manual web
  unlock. Their final outcome must be recorded before claiming completion.

- Follow-up remote inspection: Mac mini 31 targets and GrokBot 8 targets; both
  preserved all LastUsed fields. Their noninteractive sessions could not use
  the configured credentials, so installation results remain unconfirmed.
  This is not evidence that all those targets lack SSHM.


## Real enrollment and follow-up (2026-09-06)

- Browser UI approved three fresh pinned requests. Local, Mac mini and GrokBot
  joined the real account and ran E2EE Shell-capable agents at preview.13.
- Real inventory reached 51 connection variants. Local imported 37 matches;
  GrokBot added 6/matched 2; Mac mini added 9/matched 22. Distinct login/route
  variants were retained. Concurrent credential additions exposed nine
  conflicts; preview.14 fixes compatible additive merges without resolving
  differing connection settings or deletion conflicts.
- Local key migration encrypted/reprotected 10 configured keys, removed 7
  sidecars after confirmed encrypted backup and agent proof, and retained 10
  keys with unavailable unlock material. Mac mini protected 3, removed 3
  sidecars, retained 4. GrokBot's 8 already encrypted keys lacked unlock
  material and were retained unchanged. These are real-operation results.
- Post-enrollment local scan found dps-ts at 0.5.0. Its verified binary was
  updated to preview.14 at /usr/local/bin/sshm with a rollback copy; no config
  files were edited. Mac mini then detected 2 installed, 14 missing from
  checked locations, 15 unconfirmed targets. att-dev timed out from both
  available client routes.

- preview.14 published successfully after slow asset upload (544 seconds):
  Worker deployment `5d5e796d-bc70-41b4-8c7e-224fa1812595`. Local signed upgrade
  preserved the configuration byte-for-byte and production synthetic cloud
  round-trip tests passed. Compatible-merge unit and race tests passed;
  conflicting settings/deletions remain protected.


## Final convergence verified

- The next real browser unlock approved all three preview.14 agent requests.
  Each agent reached ready with 51 entries and zero conflicts. Local, Mac mini
  and GrokBot subsequently reported encrypted revision 31, dirty=false,
  pending=false. All three devices appeared online at preview.14 in the real
  browser; server rows displayed detected systems, missing/unconfirmed states
  and preview.14 for dps-ts, Mac mini and the merged GrokBot aliases.
- dps-ts's installed preview.14 also verified the production signed feed as
  current/latest with update_available=false. att-dev remains unupdated due
  to verified SSH timeouts from both routes.
- A real web Shell acceptance attempt was interrupted by visibility/automatic
  vault locking. It did not produce a verified command marker and is NOT a
  passed real-device Shell test. The test runner was stopped and the unlock
  form was reset without reading its value; the page returned to Servers.
  Previous isolated native/PTTY/ConPTY and synthetic browser Shell tests remain
  the successful Shell evidence. Cloud sync convergence is independently real.

## Preview.15 — visible deletion and signed device dispatch

- Added row-menu deletion and bulk deletion, with explicit alias/count confirmation and encrypted tombstones. Activity and obsolete conflicts are removed; original local configuration and SSH files are preserved.
- Added device actions plus vault toolbar dispatch for sync, inspect and signed client update, offline queue cancellation, durable statuses, bounded failure codes and root-signed completion receipts. Client crash/lost receipt handling does not repeat actions automatically.
- Go full suite and vet passed; affected job/merge/inspect race tests passed. Worker test suite: 7 passed. Browser build and TypeScript passed. All six Darwin/Linux/Windows amd64/arm64 clients built and signed.
- In gumusbierre99, a disposable local test account exercised actual row delete (1), bulk delete (2), sync after tombstones (0 resurrected), offline cancellation, real command executor inspection and already-current update check. All three completed jobs had valid signed receipts. The fixture confirmed byte-for-byte local config preservation and deleted its test account on exit. Desktop and 390px mobile had no body overflow. This update-job acceptance verified the already-current branch, not a remote restart.
- Real signed .14→.15 updates completed on local, Mac mini, GrokBot and dps-ts. Local/Mac/Grok retained 37/31/8 config entries with byte-for-byte config checks. att-dev still timed out at SSH/TCP and was not updated.
- Live production encrypted round-trip passed after deployment (keys/password login, CAS/merge, retry, isolation, recovery/rotation/revocation).
- Final Worker deployment at this checkpoint: f1bf4c9a-9f02-4e95-a950-2a32cde8c54a. Local/Mac/Grok agents were then browser-approved and all three reported running .15. On-disk upgrades alone require this activation step.

### Real dispatch exposed an SSH timeout gap

All three real preview.15 clients completed signed sync jobs with 51 entries. Mac mini and GrokBot completed inspection jobs (14 and 0 successfully identified targets respectively; failed/unavailable credentials remain observations, not successful connections). Local inspection stayed running after TCP connection establishment. Review found the existing `ssh.NewClientConn` calls had no handshake deadline, SOCKS negotiation only bounded TCP connect, and jump channel opening had no timeout. The blocked local agent was stopped for repair; its unfinished job must not be represented as completed.

Preview.16 adds transport-closing handshake timers (also effective for ProxyCommand transports that ignore deadlines), bounded SOCKS negotiation and jump channel opening, and idempotent bounded ProxyCommand closure. Regression fixtures accept TCP but never send an SSH banner / SOCKS response. The SSH race suite and full Go/vet suite passed before the final ProxyCommand close refinement; the affected suite was rerun after that refinement.

Preview.16 was deployed as Worker c207a439-2e6d-40f1-ad34-5dd9fcb8a49c. A real local inspection of all 37 configured connections now completed in 22.3 seconds (12 detected, 6 timeouts, 14 connection failures, 3 unconfirmed, 1 refused and 1 DNS failure), replacing the prior hang with bounded observations. The final SSH/commands/cloudsync suites and SSH vet passed after the ProxyCommand refinement. The six artifacts were rebuilt and signed before publication.

Local, Mac mini, GrokBot and dps-ts were subsequently updated through the signed .16 release. Local/Mac/Grok again passed 37/31/8 entry and byte-for-byte config preservation checks. GrokBot's direct tailnet route temporarily timed out; a private temporary local configuration used Mac mini as ProxyJump with the existing local SSH Agent identity to complete its update. The saved original connection configuration was not changed. New encrypted approvals for the three .16 agents were prepared together with immediate signed sync/inspect dispatch, to avoid an additional unlock between activation and acceptance.

At the final input checkpoint, the three .16 approval requests were ready but the browser vault was still locked. Activation and the immediate six-job rerun remain pending manual unlock; the earlier five completed .15 jobs and the isolated 22.3-second .16 inspection are the confirmed evidence. No real server entry was deleted. The temporary ProxyJump configuration and helper source were removed after remote update/start work completed. The local QA account/tab/dev server were also cleaned up.

## Resume: real preview.16 activation

The prior ten-minute approval requests had expired before the user's next unlock. Fresh requests were generated, all three matched device codes were approved in the unlocked browser, and sync plus inspect were dispatched immediately in the same browser session. Live device metadata confirmed local/Mac mini/GrokBot all running .16, online and polling the task queue. Each activation imported 51 entries with zero conflicts. Receipt verification uses the previously pinned public root, so subsequent page locking does not require another unlock merely to verify results.

Final real acceptance: all six new .16 jobs completed successfully, and every completion receipt was verified against the previously pinned vault public root. All three sync receipts reported 51 connections. Inspection receipts reported local 12, Mac mini 14 and GrokBot 0 successfully identified targets; these are per-device counts and do not imply every SSH target is reachable. All three agents remained online, reported .16 and were polling jobs. All three state files converged to revision 119 with dirty/pending false. The prior local inspection's failed receipt remains in historical job records; it was not rewritten as a success. No further unlock is pending for this activation or test cycle.

## Preview.17 — MacBook Air agent unexpectedly offline

Live inspection found no local cloud-agent process. Its log ended with `cloud request failed (HTTP 409, relay_unavailable)` while the encrypted local state remained logged in and clean at revision 119. The relay reconnect loop treated HTTP 409 (an existing agent socket) as a fatal error; runCloudAgent then exited, taking heartbeat/sync with it.

The client now retries transient 409 responses instead of exiting, preserves fatal handling for 401/403, and bounds the initial relay connection attempt to 20 seconds. Cloud relay attachments record message liveness, exclude stale agents after 90 seconds, and prune stale sockets before admitting replacements. Legacy attachments become liveness-tracked on their next message. Regression tests cover repeated 409 then successful reconnect, unchanged revocation handling, refusal of a genuinely live duplicate, and admission after the old socket becomes stale. Affected race tests, full Go/vet, eight Worker tests, and TypeScript passed. Six platform artifacts were built for preview.17.

Preview.17 deployed as Worker 1f63d0d7-2c65-48a5-8cd3-ddd04075ea7f; production encrypted round-trip passed after deployment. Local, Mac mini, GrokBot and dps-ts installed the signed .17 release. Local/Mac/Grok configuration remained byte-for-byte unchanged (37/31/8 entries). The browser was already unlocked when fresh approval requests arrived, so all three were approved without another user-input prompt. Local agent activation retained 51 encrypted entries, zero conflicts, and revision 120; live process inspection confirmed the .17 cloud agent running with no subsequent error in its new log.

Runtime readback across 85 seconds confirmed all three devices online at .17, unchanged relay epochs (no repeated reconnect churn), and advancing heartbeats/job polling. The local heartbeat advanced by 90 seconds across that interval, its agent process remained running without another error, and local encrypted state was clean at revision 122. The device page was refreshed to show the recovered online state. This is bounded runtime verification plus regression testing, not a claim of indefinite uptime.

## Preview.18 hardware and custom controls

Implemented read-only Linux/macOS/Windows hardware collectors, 512 KiB/12-second local bounds, remote SSH collection under the inspection deadline, independent encrypted device hardware and server observations, and failure-preserving snapshot merging. Added OS/CPU/memory/disk columns to both inventories, expandable complete disk records, stale/partial/unavailable indicators, custom selectors/checkboxes/validation/confirmations/tooltips and narrow-screen layout. Disk classification explicitly excludes RAM/zram, eMMC boot regions and disconnected NBD from physical/virtual disk totals while retaining their records.

Validation: full Go suite and vet passed; affected Go race suites passed; eight Worker tests and TypeScript/browser build passed. Added parsing fixtures for Linux multi-disks, unmounted devices, macOS shared APFS, Windows volumes without drive letters, overflow/failure handling, encrypted hardware round-trip, merge independence and TOML zero-free-space/64-bit capacity round-trip. A browser-side storage classification test also passed. Production encrypted round-trip passed.

Live local collector identified macOS 15.5 / Apple M4 / 10 threads / 16 GiB and 22 storage records. Real SSH inspection completed all 37 local connection variants: 14 hardware successes, with remaining targets preserving actual timeout/connection/refusal/DNS/unknown results. Successful targets included the Windows 10 Pro win-build machine with two disks, two-disk MS01/wingu and the four NVMe disks on prod-7w (its 16 unused NBD devices are listed separately). No claim that inaccessible targets or all host disks inside containers were detected.

Signed preview.18 assets built for six OS/architecture targets and published. Local/Mac mini/GrokBot/DPS updated via signature-verified feed; local/Mac/Grok inventory counts 37/31/8 and config bytes were preserved during update. Three fresh browser approvals activated .18 agents without exporting the vault master. All three reported online with decrypted hardware in the production device UI. Three sync jobs completed with 51 entries each; three inspect jobs completed (local 14, Mac mini 15, GrokBot 0 identified targets), all six receipts verified against the pinned vault root. GrokBot's local target authentication availability remains distinct from successful self hardware collection.

In gumusbierre99, synthetic-account acceptance verified OS/CPU/memory/multi-disk rows, custom group selection with End key, modal picker focus and Escape, custom required-field errors and revoke confirmation, no visible native selects, and contained 390px horizontal table overflow. Production readback confirmed all three hardware rows and, after rendering settled, zero visible native selects or native title tooltips. Final Worker deployment: 7c7f09de-706f-417d-aedc-b2af7cad4398. Published client bytes remain immutable at .18; subsequent deployment refinements changed browser presentation only.

Final lock acceptance cleared all synthetic server rows, hardware dialogs and custom tooltips; device rows no longer contained the fixture CPU model. Final Go/vet, Worker and browser storage tests passed. The long-lived opt-in browser fixture reached the Go runner default 10-minute timeout during extended manual QA (not a product test regression); its synthetic local account was explicitly deleted with HTTP 200 and its tab/dev server cleaned up. Future extended fixture runs need `go test -timeout 35m`. The two remote clients were read back at clean revision 147; the local client was later read back at clean revision 148 as periodic hardware refreshes continued. No pending local operation or dirty draft remained in those checks.


## Preview.19 / .21 resource visibility, target terminals and agent recovery

Published signed preview.19 and then preview.21 clients for six OS/architecture targets. Preview.20 deployment was stopped during asset upload; no .20 activation was confirmed. Final .21 Worker deployment: `f272a2e2-1ddf-4a47-a05b-3ac9a6685688`. Disk tables now display known filesystem/container remaining space, deduplicating APFS shared containers and their volumes/snapshots. Account-authenticated device resources are available without vault unlock; server-address records and credentials remain E2EE. Public resource validation removes mount paths, volume UUIDs and unknown fields. This supersedes the .18 lock policy above.

Server row menus can open a signed v2 SSH terminal through a trusted online agent, including targets without SSHM. Encrypted selection is resolved against the fresh verified vault, with deleted/conflicting targets rejected and original-device requirements for local proxy routes. Native v1 terminal compatibility is retained. Synthetic browser QA in gumusbierre99 verified readiness and actual SSH input/output (`TARGET:browser-ssh-proof`) through the server menu; the synthetic account was deleted on fixture shutdown. Locked-device QA confirmed CPU/RAM and 250 GiB filesystem remaining capacity with no mount path disclosure. The live production encrypted round-trip passed.

GrokBot prod-go incident: a no-environment CLI invocation failed because the managed agent had no matching key. The original same-user `.ssh/sshm-agent.sock` held eight keys including the prod-go identity; specifying it restored the exact remote execution immediately. The managed socket was atomically aliased to the existing agent inode for already running clients, preserving the previous empty socket as `socket-empty-backup-1788706119`. No SSH private key, passphrase, target address or authorized_keys was replaced. Preview.21 recognizes the original Linux socket and matches exact public keys across permitted candidates while preserving an explicit environment override. A later transient GrokBot reachability/heartbeat interruption delayed deployment; access recovered and the signed .21 update completed with all eight inventory entries and config bytes preserved. Fresh GrokBot MCP without SSH_AUTH_SOCK executed prod-go successfully after the update.

Local and Mac mini clients also updated to .21 (37 and 31 records). Mac mini's update preserved config bytes. The first local concurrent update comparison reported a changed field while other checks were running; a subsequent isolated update check passed byte-for-byte with all 37 entries, so the initial comparison is not claimed as a pass. Real Windows named-pipe signing and explicit-pipe selection tests passed on win-build; macOS MCP without SSH_AUTH_SOCK executed a harmless win-build hostname command. Linux original-agent preference, explicit override and exact-key fallback tests passed; the stale-socket case initially exposed a test fixture lifetime error, corrected by keeping the replacement agent under parent-test cleanup. Final rerun is recorded below when complete.

Final corrected Linux regression ran on GrokBot and all four cases passed; uploaded synthetic test files were removed. The full Go suite/vet, affected SSH/cloudagent race suites, TypeScript/browser build, two browser storage tests and eleven Worker tests passed. All three installed clients are .21; fresh .21 agent enrollment requests are prepared and awaiting the user's vault unlock. Existing SSH/MCP recovery is independent of that approval.
