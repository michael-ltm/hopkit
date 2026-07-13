# sshm Project Profiles and Token-Efficient Skill Design

## Goal

Make repeated project operations on shared remote machines deterministic without
breaking any existing sshm CLI, MCP, configuration, or skill workflow. A project
must resolve to one server, one stable remote workspace, and one stable artifact
contract. The default skill context must become smaller while retaining all
current server-management capabilities through progressive disclosure.

## Approved direction

Use additive project profiles plus a compact core skill.

Two smaller alternatives were rejected:

- A skill-only convention cannot persist paths or prevent a later session from
  inventing a different directory.
- Storing project paths in `Server.Notes` conflates multiple projects hosted on
  one machine and is not available through the current MCP read/write contract.

The selected design keeps server inventory and project workflow configuration as
separate concepts. Existing server-only calls remain unchanged.

## Compatibility constraints

- Existing TOML files with `version = 2` must load without manual migration.
- Existing server fields and every current MCP tool retain their names and
  argument/return behavior.
- No project profile is required for ordinary server status, one-off exec,
  onboarding, or file transfer.
- Project tools are additive. Missing profiles return a clear not-found result
  and never guess or create a remote path.
- Stored commands and paths must not contain credentials. Existing masking,
  dangerous-command filtering, host-key verification, auditing, and `reason`
  requirements continue to apply.
- POSIX and native Windows remotes are first-class targets.

## Configuration model

Add an optional top-level `projects` map and advance the schema to version 3.
Loading a version-2 file initializes an empty project map in memory; the file is
only rewritten as version 3 during a later explicit configuration write.

```toml
[projects.project_ajie]
server = "pc-e5"
local_root = "/Users/ming/Documents/code/project/ajie/project_ajie"
remote_workspace = "C:\\sshm\\workspaces\\project_ajie"
remote_runs = "C:\\sshm\\runs\\project_ajie"
artifact_path = "C:\\sshm\\artifacts\\project_ajie\\latest\\ajie_publish_tool.exe"
local_artifact_dir = "/Users/ming/Documents/code/project/ajie/project_ajie/dist"
shell = "powershell"
build_command = "python build.py onefile"
verify_command = "python -m unittest discover -s tests"
```

`Project` fields:

- `Server`: required existing sshm alias.
- `LocalRoot`: optional local source root used for identity and handoff.
- `RemoteWorkspace`: required stable source workspace.
- `RemoteRuns`: optional root for isolated timestamped build directories.
- `ArtifactPath`: required stable final artifact path.
- `LocalArtifactDir`: optional stable local delivery directory.
- `Shell`: `auto`, `posix`, `powershell`, or `cmd`; defaults to `auto`.
- `BuildCommand` and `VerifyCommand`: optional reusable commands. They are not
  executed automatically by profile reads.

Aliases use the same conservative validation as server aliases. Paths are stored
verbatim because local, POSIX, and Windows syntax differ. Project writes validate
that the referenced server exists.

## MCP surface

Keep the additive surface small to control tool-schema tokens:

1. `list_projects`: compact list containing project name, server, shell, and
   remote workspace.
2. `get_project`: full non-secret project profile.
3. `upsert_project`: create or update a profile; requires an audited `reason`.
   Empty optional values clear fields only when explicitly included.
4. `exec_project`: execute a command in the configured remote workspace, using
   the profile shell and the existing exec safety/timeout behavior. It returns
   the resolved project, alias, workdir, and normal exec result.

Existing `upload`, `download`, and transfer tools continue to move artifacts by
the exact `ArtifactPath` returned by `get_project`. A separate build orchestrator
is intentionally deferred: storing arbitrary pipelines would add complexity and
tool-schema cost before the stable profile primitive has proven sufficient.

`exec_project` accepts an optional `workdir` selector:

- `workspace` (default): `RemoteWorkspace`.
- `runs`: `RemoteRuns`; rejected when it is not configured.
- `artifact_parent`: parent directory of `ArtifactPath`.

It constructs platform-correct directory changes internally and rejects newline
or NUL characters in configured workdirs. The command itself still passes through
the existing dangerous-command filter and audit path.

## Stable build and artifact contract

The skill treats paths as a three-level contract:

- Stable source: `RemoteWorkspace`.
- Optional isolated build runs: a child of `RemoteRuns` selected explicitly by
  the task; unique run directories are healthy and prevent stale build inputs.
- Stable delivery: `ArtifactPath`. A successful build copies or moves the final
  artifact here before download.

For every project build, the workflow is:

1. Resolve the profile and run `check_ssh(mode=exec)` on its server.
2. Preflight inside the resolved workspace: print the path, verify expected
   project markers, and record source revision or source archive hash.
3. Run the configured or user-requested verification and build commands.
4. Promote the result to `ArtifactPath`.
5. Verify artifact modification time is after build start, size is non-zero,
   calculate SHA-256, and perform the project-appropriate smoke check.
6. Download to `LocalArtifactDir` when configured and confirm the local SHA-256
   matches the remote artifact evidence.

The profile prevents path guessing; it does not silently approve a stale or
unexpected checkout.

## Windows detached jobs and logs

The current Windows launcher is not a complete job contract: it returns a
PowerShell `$env:TEMP` path, while `tail_logs` invokes POSIX `tail`. Preserve
current arguments, but make log reading platform-aware.

- Resolve a concrete Windows log path before returning from detached launch.
- Return `pid` when the launcher provides it.
- Make `tail_logs` accept `platform=auto|posix|windows`; auto-detect using the
  same remote platform probe as detach.
- POSIX uses `tail -n`; Windows uses PowerShell `Get-Content -Tail`.
- Update tool descriptions so they no longer claim detach is POSIX-only.
- Until this path passes unit and real-host verification, the skill uses normal
  `exec` with a long timeout and explicit log redirection for Windows builds.

A durable `job_status` API is outside this increment. PID and readable logs fix
the current broken promise without inventing a larger scheduler.

## Token-use design

Token savings come from eliminating repeated discovery and from progressive
skill disclosure, not from deleting capabilities.

### Core skill budget

- `SKILL.md` target: no more than 500 whitespace-delimited words.
- Keep only tool-selection rules, safety invariants, error policy, and pointers
  to conditional references in the core.
- Do not duplicate complete tool argument tables in the core.
- Replace unconditional "See ..." wording with explicit routing:
  - read `references/project-workflows.md` only for build, package, deploy, or
    repeated project work;
  - read `references/onboarding.md` only for adding/hardening hosts;
  - read `quick-reference.md` only when exact tool fields are not already
    available from MCP schemas.

### Runtime efficiency

- Resolve a profile once per task and reuse its returned values.
- Do not call `list_servers` when the user supplied a valid project profile.
- Use `check_ssh` once before the operation; do not pair it with redundant TCP
  probes unless diagnosing a failure.
- Use exact artifact paths instead of recursive remote searches.
- Prefer compact command output and targeted log tails; do not return full build
  logs unless requested or needed for diagnosis.
- Keep tool descriptions short and move examples into conditional references.

### Measurement

Record the existing combined skill word/byte counts as a baseline. Add an
automated test that keeps the core `SKILL.md` within 500 words and confirms every
conditional reference named by the core exists. Report before/after core and
common project-workflow sizes. Tool behavior compatibility is proven by the full
Go test suite, not by documentation size alone.

## Error handling

- Replace the skill rule "surface any tool error and stop" with "do not repeat
  the same failed mutation blindly." Read-only diagnosis and safe alternatives
  remain allowed.
- Unknown projects list available project names without revealing secrets.
- A profile referencing a removed server is reported as invalid and is not run.
- `exec_project` returns profile-resolution failures before dialing SSH.
- Windows platform detection failure falls back to the profile `Shell`, then to
  the existing POSIX behavior only when both are `auto`.
- Changed host keys and dangerous commands retain current hard stops.

## Testing

Use test-first development for each behavior:

- Config v2 loads with an empty project map; v3 round-trips all project fields.
- Project writes reject missing servers and preserve unspecified fields.
- Project reads are deterministic and sorted.
- `exec_project` produces correct POSIX, PowerShell, and cmd workdir wrappers,
  rejects invalid paths, and uses existing safety/audit behavior.
- Windows detach returns a concrete log path and PID when available.
- `tail_logs` generates platform-correct commands.
- Existing MCP registration and behavior tests remain green.
- Core skill word budget and conditional reference existence tests pass.
- Cross-build gates remain green for Linux, macOS, and Windows.

Skill evaluation uses realistic prompts covering a repeated `pc-e5` EXE build,
two projects sharing one host, a Linux deployment, onboarding, and a one-off
server command. Assertions check that the profile path is reused, redundant
probes and recursive searches are absent, Windows detach is avoided until
verified, and artifact evidence is returned.

## Release

Bump the binary, plugin manifest, and marketplace versions together. Add a test
or release check that fails when these declared versions diverge. Update the
changelog and package the revised skill so installed clients do not remain on an
older manifest version.
