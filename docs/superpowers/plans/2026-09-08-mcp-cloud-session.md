# MCP cloud session implementation plan

**Goal:** Browser approval unlocks cloud-backed operations inside the requesting MCP without exposing credentials to the AI.
**Architecture:** Process-local cloud session plus an explicit SSH resolver callback. Existing signed browser grant and authenticated encrypted snapshots remain the trust boundary.
**Tech Stack:** Go, existing cloudsync crypto, MCP stdio, x/crypto/ssh.
**Spec:** docs/superpowers/specs/2026-09-08-mcp-cloud-session.md

## Tasks
- [x] Session owner and lifecycle: internal/mcp/cloud_session.go. NewCloudSession(path string) *CloudSession; Begin(ctx context.Context) (CloudSessionStatus,error); Status() CloudSessionStatus; Close(); Resolve(ctx context.Context,target *config.Server,opts ssh.BuildOpts) (*config.Server,ssh.BuildOpts,func(),error). Async 10-minute request, 15-minute idle and one-hour hard limit; mutex and timer guard secrets. Remote snapshot validation on each resolution, no persistent session token. Test revoked/expired/tampered paths before integration.
- [x] SSH adapter and all MCP callers: ssh.BuildOpts.ResolveCloud callback with signature func(*config.Server,BuildOpts)(*config.Server,BuildOpts,func(),error); Dial invokes once for cloud binding and defers cleanup until handshake. Deps.CloudSession *CloudSession; deps.sshOptions(ctx,opts) attaches resolver. Route all MCP SSH calls including status/bootstrap/transfer. Verify native callers and fail-closed cloud behavior with real tests.
- [x] Tool handlers and cleanup: internal/mcp/tools_cloud.go, server.go and commands/mcp.go. Only full MCP registers cloud_unlock, cloud_unlock_status, cloud_lock; reason required for begin/lock; reject unexpected fields; public status only. CLI creates session and defers Close. Tests exercise protocol schema and sanitized output.
- [x] Security/integration review: real signed synthetic browser approval followed by cloud credential SSH execution, fail-closed rollback/revocation and lock. Update repo skill cloud-sync guidance and docs. Run go test with race where appropriate; retain known unrelated baseline failure.

Ruling: work in the user's active checkout to preserve and include the prior cloud error fixes; no automatic commit or publish. The user explicitly authorized fixing this flow with security as the core requirement. Parallel bounded implementation follows subagent-driven-development; session owner and MCP adapter are separate files with the contract above.


## Verification and delivery

- `go test -race -p 1 ./internal/mcp -count=1` passed, including real signed browser grant followed by MCP SSH execution, revocation, rollback, tamper, expiry and output isolation.
- `go test -race -p 1 ./internal/ssh -count=1` passed, including strict routes, native regressions and real SSH handshake.
- Repository-wide tests passed except two independently reproduced baseline failures: Windows pairing command length and generated public key permissions under this environment's umask.
- Native binary built and stdio protocol smoke checked. Installed at Grok's configured `/home/ming/.local/bin/sshm` as `0.8.0-cloud-preview.33-mcp-session.1`, preserving a timestamped binary backup. Updated only installed cloud-sync guidance, also backed up.
- Grok must restart its existing MCP process and obtain a fresh approval in that process. The old process's grant is deliberately not transferable. No live browser approval was impersonated; validation used synthetic crypto and local SSH servers.
- Final security review cleared direct-route fallback and environment-proxy bypasses using StrictRoute; no additional blocking findings.

- Windows amd64 cross-build passed after using workspace output to avoid the temporary filesystem quota; the temporary build artifact was removed.
