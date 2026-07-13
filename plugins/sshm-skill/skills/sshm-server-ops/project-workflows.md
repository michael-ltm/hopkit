# Project Build and Artifact Workflows

Project profiles make remote paths and commands deterministic. Treat the
profile as the contract; never reconstruct it from a repository name, a temp
directory, another machine, or an earlier run.

## Resolve or create the profile

1. Call `list_projects`, then `get_project` for the named project.
2. If it is absent or stale, obtain the exact values from the user or an
   authoritative project config. Use `upsert_project` only with confirmed
   values and a specific `reason`.
3. A new profile requires an existing server alias, `remote_workspace`, and
   `artifact_path`. Optional fields are `local_root`, `remote_runs`,
   `local_artifact_dir`, `shell`, `build_command`, and `verify_command`.

## Stable path contract

- `remote_workspace` is the durable source/build tree. Reuse it across runs;
  do not silently build in `$HOME`, `%TEMP%`, or a guessed checkout.
- `remote_runs` is a durable root for uniquely named run directories, logs,
  and metadata. Use `workdir=runs` only when it is configured; create a unique
  child for each run so concurrent or previous evidence is not overwritten.
- `artifact_path` is the canonical published artifact. Build elsewhere when
  practical, verify the candidate, then replace this path deliberately.
- `local_root` and `local_artifact_dir` are local contracts. If either needed
  path is absent, ask rather than choosing one.

`exec_project` defaults to `workdir=workspace`; it also supports `runs` and
`artifact_parent`. It resolves POSIX, PowerShell, or cmd quoting from the
profile and preserves normal exec safety, audit, timeout, and detach behavior.

## Build, verify, and retrieve

1. Use the core workflow's single `check_ssh` preflight. Stage the exact source
   into the configured workspace with `upload`, or use `transfer_start` for a
   large archive. Supply SHA-256 when a known digest exists.
2. Run the profile's `build_command` through `exec_project`. If no build command
   is configured, ask for it; do not invent one.
3. Windows builds and EXE packaging often exceed 60 seconds. Prefer a normal
   `exec_project` with a realistic long `timeout_seconds` (or `0`). If detached
   launch lacks a usable `log_path`, inspect its recovery metadata and fall
   back once to non-detached long-timeout execution with output redirected to a
   known file under configured `remote_runs` (ask if it is absent). Read it with
   `tail_logs platform=windows`; do not relaunch the build blindly.
4. An exit code of zero is not delivery proof. Verify all three:
   - **Freshness:** size and modification time belong to this run, or the digest
     changed from the pre-build artifact as expected.
   - **SHA-256:** compute it remotely and preserve/compare it during download.
   - **Smoke:** run the configured `verify_command`. If none exists, ask which
     side-effect-free command proves the artifact starts or reports its version.
5. Download the exact `artifact_path` into `local_artifact_dir`, using resume or
   background transfer when needed. Report exact source/destination paths,
   bytes, SHA-256, freshness evidence, and smoke-test result.
