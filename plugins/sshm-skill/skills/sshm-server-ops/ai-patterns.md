# sshm Server-Only Patterns

Use these sequences only when no project profile is involved.

| Intent | Minimal sequence |
|---|---|
| Deploy | `check_ssh` once → `upload` or `exec` → restart with `exec` → `get_status` |
| Follow a detached job | `exec detach=true` → `tail_logs` using returned `log_path` and `platform` |
| Diagnose an incident | `get_status` → `tail_logs` → read-only `exec` diagnostics |
| Apply one command to several hosts | inspect aliases → `exec_multi` → investigate only failed aliases |
| Move a large file | `transfer_start` → poll `transfer_status` → verify returned SHA-256 |

For project builds or artifacts, use
[project-workflows.md](project-workflows.md). For new-host setup, use
[onboarding.md](onboarding.md). Load neither unless that workflow applies.
