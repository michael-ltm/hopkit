# SSHM preview.25 delivery

Production: https://sshm.yunmini.net — Worker `7c207de0-6059-4743-8481-34f1e253040f`.
Six signed clients: macOS/Linux/Windows × AMD64/ARM64. Local Mac command upgraded through the signed updater to `0.8.0-cloud-preview.25` with a rollback binary.

Delivered:
- Installer PATH guidance and a website command that activates the parent terminal PATH; binary downloads keep correct names/content types; logged-in logo navigation stays on the homepage.
- Post-login sync choice, including `--import-local`; encrypted credentials stay in the vault. `cloud sync` and the new root `sync` update the local connection list.
- Recent successful connection ordering for both terminal lists, stable alias ordering for ties, never-connected entries last.
- `cloud add-device` publishes a native device with a stable identity; `cloud enable` publishes this device and explicitly runs the existing encrypted terminal agent. Native clients use the signed/encrypted relay through `sshm connect` without SSH address/port or new private-key files.
- Website device membership column and quick-add action. Locked membership stays unknown; adding, deleting and re-adding update the state. Same device ID is idempotent; SSH connection variants are retained separately.
- Deletions remove cloud references and bound local records on sync. Local records receive a private config backup before removal. Default, protected and project/jump-host dependent records remain with an explicit sync warning. SSH key files and remote hosts are not deleted.

Evidence:
- Full Go test suite and vet passed; relevant race tests passed.
- 14 Worker tests and Node installer/browser tests passed, including native-client role authorization, ciphertext relay/revocation, and cross-language device-ID deduplication.
- Real CLI against production: login skip/accept, empty-device sync/list, repeated sync, password SSH, device quick-add/enable and another native CLI connecting to its terminal passed.
- Real macOS, Linux and Windows native terminals connected in both directions; invalid vault signing keys were rejected and device revocation closed the active terminal.
- Browser QA in gumusbierre99 used an isolated local synthetic account. Add 55→56, duplicate stayed 56, delete 56→55; independent CLI sync removed the deleted entry. Membership switched correctly. Table fits its 1150px viewport without horizontal overflow.
- Live production page has the membership column. Fresh MCP runtime reports preview.25 and a real GrokBot SSH check succeeded.
- Synthetic accounts were deleted; temporary Linux/Windows test directories were removed; local test worker stopped. Existing running cloud agents were not restarted.

Limits:
- New client relay supports interactive terminals. Non-interactive device exec/MCP has not been implemented; existing SSH key/agent automation remains available.
- The target must keep `cloud enable` running. Restart requires vault unlock; no master key is persisted unencrypted for unattended restart.
- Membership requires vault unlock because it is derived from encrypted inventory. Resource information remains viewable without vault unlock.
- Plugin-managed Codex/Claude skill installations were retained by the updater; already-running MCP/cloud-agent processes keep their loaded version until restarted.
- No commit or push was performed; existing unrelated workspace changes were preserved.
