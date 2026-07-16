# Remote Reverse and Dynamic-Debug Workflows

Use this workflow only for software and machines the user owns or is authorized
to analyze. Treat unknown executables as hostile: select a disposable lab/VM,
never a production server. If inventory metadata does not prove isolation, stop
and ask rather than choosing a convenient online host.

## Route the analysis before choosing tools

- Android/Java (`apk`, `dex`, `jar`, `aar`, `class`, `smali`): use the
  `jadx-analyze` skill for static structure and read its summary first.
- Native binaries (`exe`, `dll`, `so`, `dylib`): use `ida-export` for headless
  static export; start from its manifest, strings, imports, and function index.
- Runtime-only behavior, breakpoints, memory, trace, or anti-debug validation:
  use the `dynamic-reverse` project only after its live `doctor`/capability
  output proves the requested backend and target are supported. A tool's mere
  presence, a cross-build, or one CDB smoke record is not a production support claim.

Static triage should usually precede dynamic execution so the remote session has
specific modules, functions, hypotheses, and stop conditions.

## Select and bind the remote lab

1. Call `find_servers` with concrete requirements such as OS, architecture,
   isolation, and tools (`windows x64 disposable dynamic-debug cdb`). Inspect
   the winning `description`, `tags`, and `group`; then call `get_server` once.
2. Resolve the named project with `get_project`. The profile is the contract for
   workspace, runs/evidence root, shell, build, and artifact paths. Do not guess
   these from a repository name or a previous machine.
3. Run one `check_ssh(mode=exec)`. Record target and tool SHA-256 before upload
   or execution. Refuse an unexpected checkout, binary, backend, or tool digest.
4. Use `exec_project`. Give each concurrent target a unique session directory
   below configured `remote_runs`; keep commands, logs, dumps, journals, and
   cleanup scoped to that session. Never reuse a mutable global debugger session.
5. For a long Windows operation, follow the non-detached contract in
   [project-workflows.md](project-workflows.md) until that host's detached path
   has real launch/log/completion evidence. Do not blindly relaunch after a
   timeout or transport loss; inspect the known log and process state first.

Report the chosen alias and description, authorization/isolation basis, exact
workspace/session paths, source and target digests, backend/tool versions,
commands, exit state, and evidence paths. Clearly separate static findings,
runtime observations, and unverified hypotheses.
