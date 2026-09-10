# In-place browser unlock and key passphrase safety

## Browser behavior

The devices approval button remains enabled while locked and opens a local unlock dialog. It resumes only the selected action, then requires the device verification code. Device task dispatch, terminal opening, adding a device to the vault and membership inspection use the same gate. The existing vault-page form remains available.

Cancellation, navigation and locking invalidate pending unlock/action tickets. A decrypted result from a cancelled attempt is closed. Approval re-fetches the exact request and checks identity, public key, expiry and displayed request properties. Dismissing the approval dialog during a network/crypto await prevents the approval POST. Phrase fields clear on submission, completion and cancellation; the phrase stays within browser decryption.

Validation: Node gate tests, TypeScript checks, all cloud tests (14 Node tests + 18 Worker tests), and deployment dry-run passed. A new Dev 1 tab against a local fixture used the real UI bundle and a real Go-generated encrypted synthetic vault. Wrong phrase remained in the modal, correct phrase returned to the same /devices approval dialog, wrong pairing code and cancellation issued no grant; correct code issued one encrypted grant. Navigation during pending request did not reopen approval. Device jobs resumed in place. 390px viewport had no horizontal overflow and the modal/input remained visible.

Production publication is pending an authenticated Cloudflare Wrangler session. Existing signed download assets were restored and signature/hash checked for a UI-only deployment; they were not rebuilt or re-signed.

## Key behavior

New gen-key, pair and provision keys use a hidden confirmed user-managed passphrase, or explicit --passphrase-file automation input on supported platforms. MCP gen_key requires passphrase_file; no inline secret argument is accepted. New flows no longer create .passphrase sidecars, print a key passphrase or generate an unrecoverable random phrase. Existing keys and recovery files are not deleted.

File input rejects symlinks, nonregular files, unsafe Unix permissions, oversized/multiline/empty data and races at open. Windows file input fails closed until ACL validation is available; interactive input remains supported. Key generation refuses both existing private and public outputs, including dangling symlinks, with exclusive creation. Rollback never deletes prior user recovery files. macOS askpass now uses a private FIFO with a fixed non-secret script, so the phrase is not written into a temporary file. Cancellation terminates helper processes and joins the writer; subprocess errors do not expose output. Linux race tests and Darwin compilation passed; macOS keychain runtime was not tested.

A metadata-only check found no .passphrase files in this user's default ~/.ssh and no key_path entries in the default config. This is not a whole-disk audit. No actual private key or phrase contents were read. Existing recovery files elsewhere should only be removed after verified encrypted backup and signing checks (the cloud harden workflow already performs these checks).

## Copying local files

The local server list and config metadata are plaintext. Only vault credentials are encrypted; a copied ciphertext can be attacked offline if its phrase is weak. Recovery codes, unencrypted native keys, private keys paired with plaintext phrase files, active ssh-agent access or process memory are separate access paths. state.json contains an account bearer token as well as encrypted snapshots; copying a valid token can impersonate its service session but does not alone decrypt the vault. Do not promise that copying the whole SSHM directory is harmless.

## Local installation and final checks

Installed local client 0.8.0-cloud-preview.33-mcp-session.2 and updated installed onboarding/quick-reference skill references with backups. MCP stdio smoke verified session tools and initially locked state. Relevant MCP, keystore, SSH, cloudsync, commands and keys race tests passed; final read-only review found no remaining blockers. The full-suite baseline still has unrelated Windows launcher-length and public-file umask expectation failures. Existing running MCP processes must restart to load the new executable.
