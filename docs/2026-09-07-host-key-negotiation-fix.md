# SSH host-key negotiation repair — preview.22

The BWG incident exposed two independent failures. Its Xray listener was running,
but the public firewalld zone did not allow TCP 443 after boot. Restoring that
port in runtime and permanent configuration recovered proxy requests. SSHM Cloud
was not in the local MCP-to-SSH connection path.

SSHM also negotiated the library's default host-key algorithm without considering
the address's existing known_hosts records. A server offering ECDSA and Ed25519
could therefore select ECDSA even when the client already trusted its unchanged
Ed25519 key. The callback rejected the unrecognized ECDSA key as a possible host
identity change. Adding another trusted algorithm was a workaround, not the
underlying repair.

## Implementation

- BuildClientConfig now orders host-key algorithms using existing trust for the
  exact address and port. Matching remains delegated to x/crypto/ssh/knownhosts,
  including hashed hosts, wildcard/negation and IPv6 addresses.
- RSA SHA-2 and host certificate authorities remain supported. The original
  callback still verifies the selected key and rejects changed or revoked keys.
  Negotiation does not rewrite known_hosts, fetch replacement keys or skip checks.
- Mismatch errors show the received algorithm/fingerprint and require independent
  identity verification instead of recommending removal of stored trust.
- MCP get_server/check_ssh report runtime_version and inventory_source=local.
  The updater explains that resident MCP/cloud processes need reactivation.
- BWG discovery metadata now includes BWG and 搬瓦工; addresses and credentials
  were not changed by that metadata update.

## Verification

The regression first failed on the old code with a real loopback SSH handshake,
including a hashed nonstandard-port entry. The fixed suite passes those cases,
RSA SHA-2, CA certificates, unknown-host pinning, changed-key rejection, revocation,
wildcards, negation and IPv6. Full Go tests and vet passed, followed by SSH/MCP
race tests and the final affected command/MCP tests. Six Darwin/Linux/Windows
amd64/arm64 clients built. Two browser storage tests and eleven Worker tests
passed. The deployed synthetic encrypted cloud round-trip passed and cleaned up
its disposable account; this is not a real-account shell activation test.

A separate private test HOME retained only BWG's original Ed25519 known_hosts
entry. Against the real server, preview.21 failed with the mismatch; the fixed
build executed hostname successfully. Both attempts preserved that trust file
byte-for-byte. Fresh installed preview.22 MCP processes then successfully executed
hostname through both existing BWG public and Tailscale aliases.

## Release and activation

Signed release: 0.8.0-cloud-preview.22. Worker deployment:
b1970f71-ff88-4594-af97-27399a6a8de2. The existing signed feed verifies .22 as
current/latest. Installed binaries were upgraded on the local Mac, Mac mini,
GrokBot and DPS, retaining updater rollback copies. Mac mini, GrokBot and DPS
configuration byte comparisons passed. The local comparison ran concurrently
with SSHM activity writes and differed; it is not claimed as a byte-preservation
pass.

Replacing a binary cannot update already-loaded code. Existing Codex/Claude MCP
processes need their host restarted/reloaded. Existing cloud agents retain their
loaded version until restarted and approved/unlocked through the existing flow.
This task did not terminate those agents or claim their .22 activation. Codex
computer control was explicitly blocked by the tool, so the current application's
MCP reload remains a user action. Newly launched .22 MCP behavior is live verified.

The checkout already contained the Cloud implementation and other uncommitted
work. Those edits were retained; this task did not commit or push them.
