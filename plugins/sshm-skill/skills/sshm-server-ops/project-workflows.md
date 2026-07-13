# Project Build and Artifact Workflows

Project profiles make paths and commands deterministic. Treat the profile as
the contract; never reconstruct it from a repository name, temporary directory,
another machine, or earlier run.

## Resolve or create the profile

1. Resolve the profile once: call `list_projects`, then `get_project`, and reuse
   the returned values throughout the task.
2. If it is absent or stale, obtain exact values from the user or an
   authoritative project config. Use `upsert_project` only with confirmed
   values and a specific `reason`.
3. A new profile requires an existing server alias, `remote_workspace`, and
   `artifact_path`. Optional fields are `local_root`, `remote_runs`,
   `local_artifact_dir`, `shell`, `build_command`, and `verify_command`.

## Stable path contract

- `remote_workspace` is the durable source/build tree. Reuse it; do not build
  silently in `$HOME`, `%TEMP%`, or a guessed checkout.
- `remote_runs` is the durable root for uniquely named run directories, logs,
  and metadata. Use `workdir=runs` only when configured, and create a unique
  child so concurrent or previous evidence is not overwritten.
- `artifact_path` is the canonical published artifact, not merely a build
  output guess. Validate a candidate before deliberately replacing this path.
- `local_root` and `local_artifact_dir` are local contracts. Ask when a needed
  path is absent instead of choosing one.

`exec_project` defaults to `workdir=workspace`; it also supports `runs` and
`artifact_parent`. It resolves profile shell quoting while preserving normal
exec safety, auditing, timeout, and detach behavior.

## Verified build, promotion, and retrieval

Follow this order for every project build:

1. Run exactly one `check_ssh(mode=exec)` on the profile server before the first
   SSH-dependent operation. Reuse that result unless connectivity changes.
2. Stage only the exact requested source when transfer is needed, supplying its
   known SHA-256. Then preflight inside `remote_workspace`: print the resolved
   workspace path, verify expected project markers, and record the source
   revision or source archive SHA-256. Stop on an unexpected checkout.
3. Before verification or compilation, record the build start time and the
   canonical artifact's pre-build artifact state and digest: existence,
   modification time, size, and SHA-256 when present.
4. Run the configured `verify_command` or the exact user-requested verification
   command before building. This is pre-build verification only; its success is
   not post-build artifact smoke evidence.
5. Run the configured `build_command` through `exec_project`. Ask if it is
   absent; never invent a command or search recursively for output.
6. Validate the candidate artifact at its exact expected output path, including
   identity and non-zero size. Then explicitly promote, copy, or move it to the
   canonical `artifact_path`; do not treat the candidate path as delivery.
7. After promotion, verify the canonical artifact's modification time is after
   the recorded build start, it has non-zero size, and its SHA-256 is recorded.
   Compare this evidence with the pre-build state and digest to reject stale
   output.
8. Run an independent, side-effect-free artifact smoke command against the
   canonical artifact and preserve its separate result. A version/help probe or
   controlled launch may qualify; ask for the project-appropriate command when
   none is authoritative. Never substitute `verify_command` evidence.
9. When configured, download remote `artifact_path` to an exact file under
   `local_artifact_dir`: join that directory with the `artifact_path` basename
   and pass the resulting file as `local_path`, never the directory itself.
   Confirm the local SHA-256 matches the remote evidence.

Report one compact evidence table: workspace/source, build start, pre/post
artifact, promotion, exact paths, bytes, SHA-256, smoke. Do not narrate
successful steps or quote full logs unless requested.

## Windows builds before detached execution is verified

Until detached Windows execution passes both unit and real-host verification,
use non-detached `exec_project` with `detach=false` from the outset for Windows
builds. Set a realistic long `timeout_seconds` (or `0`) and redirect stdout and
stderr explicitly to a known log file under configured `remote_runs`; ask for
that path if missing. Read the log with `tail_logs platform=windows`.

If a transport or timeout result leaves job state unknown, inspect the known
log, any returned PID, and remote process evidence before deciding what
happened. Do not immediately relaunch. Start another build only after evidence
shows the prior job is not running and the workspace is safe to reuse.
