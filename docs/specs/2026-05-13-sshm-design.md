# sshm — Design Specification

**Date**: 2026-05-13
**Author**: ming (michael-ltm)
**Status**: Draft — awaiting review
**Repo (planned)**: `github.com/michael-ltm/sshm`
**License**: MIT

---

## 1. Vision & Positioning

`sshm` is a cross-platform SSH connection manager built for the AI-assisted developer. It combines:

- A **pretty CLI/TUI** for humans — fast list, search, status icons, guided wizards.
- A **first-class MCP server** so any AI coding assistant (Claude Code, Codex, Cursor, Gemini CLI) can manage servers directly: list, connect, exec, bootstrap, inspect.
- A **safe execution surface** with dangerous-command filtering, sensitive-data masking, and per-action audit logging.

It is **not** a cloud provisioner. v1 manages and initializes servers that already exist (you have an IP and credentials). Cloud-provider API integration (Aliyun/AWS/etc) is deferred to v2+.

### Non-goals (explicitly out of scope for v1)

- Implementing the SSH protocol (use `golang.org/x/crypto/ssh`)
- Web UI / Electron / desktop GUI
- Multi-user / RBAC
- Built-in cloud sync of configuration
- Storing user passwords in plain config files
- Cloud-provider VM provisioning APIs
- Session recording / replay
- Encrypted secrets vault

---

## 2. Target Users

1. **Solo developers / freelancers** who manage 3–30 personal or client servers across multiple cloud providers.
2. **AI-pair-programming users** who want their AI assistant to be able to act on servers (deploy, restart, inspect logs) without copy-pasting SSH commands.
3. **Sysadmins** who want a faster, prettier alternative to manually editing `~/.ssh/config`.

---

## 3. Technology Stack

| Concern | Choice | Rationale |
|---|---|---|
| Language | Go 1.22+ | Single static binary, no runtime dependency, fast cross-compile to Win/Mac/Linux |
| CLI framework | `spf13/cobra` + `viper` | Industry standard, generates shell completions, good help text |
| TUI rendering | `charmbracelet/bubbletea` + `lipgloss` | Best-in-class Go TUI; used by `gh`, `lazygit`, `k9s` |
| Interactive forms | `charmbracelet/huh` | Wizard-style prompts for `sshm add` |
| SSH client | `golang.org/x/crypto/ssh` (+ `pkg/sftp` for file ops) | Standard, audited |
| Config format | TOML via `BurntSushi/toml` | Human-readable; easier than YAML for users to hand-edit |
| MCP server | `mark3labs/mcp-go` | Maintained Go SDK; supports stdio transport |
| Release tooling | GoReleaser + GitHub Actions | One-command multi-platform release |
| Test framework | `testify` + Dockerized sshd in CI | Real SSH integration tests |
| Structured logging | `log/slog` (stdlib) | No extra dependency |

---

## 4. Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                        sshm (single binary)                        │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌────────────┐   ┌──────────────┐   ┌──────────────────────────┐  │
│  │  CLI (cobra)│   │  TUI         │   │  MCP server (stdio)      │  │
│  │  sshm ls    │   │  bubbletea   │   │  sshm mcp                │  │
│  │  sshm add   │   │  live status │   │  exposes tools for AI    │  │
│  │  sshm c …   │   └──────────────┘   └──────────────────────────┘  │
│  └─────────────┘                                                    │
│         │                  │                          │             │
│         └──────┬───────────┴──────────────┬───────────┘             │
│                ▼                          ▼                         │
│  ┌──────────────────────────┐   ┌─────────────────────────────┐    │
│  │  Core services           │   │  Safety / audit             │    │
│  │  • config (TOML)         │   │  • dangerous-command filter │    │
│  │  • ssh (connect/exec)    │   │  • sensitive-data masking   │    │
│  │  • status (probe + meta) │   │  • per-action audit log     │    │
│  │  • bootstrap (init host) │   │                             │    │
│  │  • keys (gen + copy-id)  │   │                             │    │
│  └──────────────────────────┘   └─────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌──────────────────────────────┐
              │ ~/.config/sshm/config.toml   │  ← source of truth
              │ ~/.config/sshm/audit.log     │
              │ ~/.config/sshm/snapshots/    │  ← optional per-server cache
              └──────────────────────────────┘
```

### Module boundaries (`internal/`)

Each module is one focused responsibility, owns its own data structures, and depends only on what its function signatures declare.

| Package | Responsibility | Depends on |
|---|---|---|
| `config` | Load/save TOML, migrations, defaults | stdlib only |
| `ssh` | Build clients, exec commands, sftp | `config`, `crypto/ssh` |
| `keys` | Generate ed25519/rsa, copy-id flow | `ssh` |
| `status` | Probe reachability, collect uptime/disk/mem | `ssh` |
| `bootstrap` | Embed and run init scripts on remote | `ssh`, `embed` |
| `tui` | bubbletea models for list view | `config`, `status` |
| `wizard` | huh forms for add/edit | `config`, `ssh`, `keys` |
| `ui` | lipgloss styles, icons, color, table render | none |
| `mcp` | MCP server, tool handlers | all of the above + `safety` |
| `safety` | Command pattern filter, output masker, audit | stdlib only |

A module can be reasoned about independently: change `tui` internals without touching `config`, swap `ssh` for a fake in tests without touching `mcp`.

---

## 5. Data Model

### `~/.config/sshm/config.toml`

```toml
version = 2
default = "aliyun-jiang"

[ui]
icons = "unicode"            # "unicode" | "ascii" (Win cmd.exe auto-falls-back to ascii)
color = "auto"               # "auto" | "always" | "never"

[mcp]
allow_write = true           # AI may run add_server / bootstrap / etc.
require_reason = true        # writes must include a `reason` arg
exec_safety = "strict"       # "strict" | "permissive" | "off"

[servers.aliyun-jiang]
label        = "Aliyun ECS - jiang"
host         = "203.0.113.10"
port         = 22
user         = "ming"
auth         = "key"                                # "key" | "password" | "agent"
key_path     = "~/.ssh/id_ed25519_aliyun_jiang"     # only if auth=key
tags         = ["aliyun", "prod"]
group        = "aliyun"
notes        = "APK reverse engineering host"
init_state   = "bootstrapped"                       # "raw" | "bootstrapped"
last_seen    = "2026-05-13T01:22:26+08:00"
last_status  = "online"                             # online | offline | unknown
proxy_jump   = ""
proxy_command = ""                                  # e.g. "nc -X 5 -x 127.0.0.1:7890 %h %p"
forwards     = []                                   # ["L:9000:localhost:9000"]
```

Storage **never holds passwords**. If `auth = "password"`, the password is read at connect time from the OS keychain (macOS Keychain / Windows Credential Manager / libsecret) under service name `sshm/<alias>`. If keychain is unavailable, prompt every time.

### Cross-platform paths

| OS | Config dir | Audit log |
|---|---|---|
| macOS / Linux | `${XDG_CONFIG_HOME:-~/.config}/sshm/` | `~/.config/sshm/audit.log` |
| Windows | `%APPDATA%\sshm\` | `%APPDATA%\sshm\audit.log` |

---

## 6. Command Surface

All commands accept `--json` for machine-readable output.

### Server management

| Command | Behavior |
|---|---|
| `sshm` | Launch TUI (live list, search, connect with Enter) |
| `sshm ls` \| `sshm list` | Table of servers with status icon, host, user, auth, tags, last-seen |
| `sshm add` | Interactive wizard (huh) |
| `sshm add --quick <alias> <user@host[:port]> [-i <key>]` | Non-interactive |
| `sshm edit <alias>` | Wizard pre-filled |
| `sshm rm <alias>` | Remove (confirm prompt; `-y` to skip) |
| `sshm show <alias>` | Detailed view |
| `sshm tag {add,rm,ls} <alias> [tags...]` | Tag management |
| `sshm group ls` | Group view |

### Connection & execution

| Command | Behavior |
|---|---|
| `sshm c <alias>` \| `sshm connect <alias>` | Open interactive SSH session |
| `sshm exec <alias> <cmd...>` | Run command, stream output |
| `sshm exec --all [--tag <t>] <cmd...>` | Run across multiple, parallel, prefixed output |
| `sshm test [<alias>] [--all] [--timeout 5s]` | Connectivity check |
| `sshm copy-id <alias>` | Push local public key to remote `authorized_keys` |
| `sshm gen-key <alias>` | Generate ed25519 keypair scoped to this server |

### Server lifecycle

| Command | Behavior |
|---|---|
| `sshm init <alias>` | Run bootstrap on remote: install jq, fail2ban, firewalld basics; ensure non-root sudo user exists; disable password SSH; disable root SSH; mark `init_state = "bootstrapped"` |
| `sshm status <alias>` | Snapshot: uptime, load, mem, disk, listening ports, recent failed logins |

### Interop

| Command | Behavior |
|---|---|
| `sshm import` | Pull entries from `~/.ssh/config` |
| `sshm export` | Write managed entries back into `~/.ssh/config` inside a `# >>> sshm-managed >>>` / `# <<< sshm-managed` block — never touches user's hand-written entries |
| `sshm mcp` | Start MCP server on stdio (used by AI hosts) |
| `sshm completion {bash,zsh,fish,powershell}` | Emit shell completion |

---

## 7. `sshm add` Wizard

Goal: any user who has an IP, port, username, and one auth method should reach a working `ssh aliyun-jiang` in under one minute.

```
┌─ Add new server ──────────────────────────────┐
│ Alias        : aliyun-jiang                   │
│ Host / IP    : 203.0.113.10                   │
│ Port         : 22                             │
│ User         : ming                           │
│                                               │
│ Auth method:                                  │
│   ◉ Use existing key (pick from ~/.ssh)       │
│   ○ Generate new ed25519 key for this host    │
│   ○ Password                                  │
│   ○ ssh-agent                                 │
│                                               │
│ Tags (comma)  : aliyun, prod                  │
│ Group         : aliyun                        │
│                                               │
│ ☑ Test connection after save                  │
│ □ Push public key to remote now (copy-id)     │
│ □ Run bootstrap initialization                │
└───────────────────────────────────────────────┘
  Tab / Shift+Tab — switch field
  Enter — confirm     Esc — cancel
```

On confirm:

1. Validate (alias unique, host non-empty, port 1–65535, key file exists).
2. Save TOML entry.
3. If "test" — open SSH, run `echo OK`, show round-trip + remote hostname, color-coded icon.
4. If test fails: show specific error (DNS / timeout / auth / handshake), suggest fix, prompt **"save anyway? retry? cancel?"**.
5. If "copy-id" — prompt for the password **once** (in TTY, not stored), use `ssh-copy-id`-equivalent flow, verify by reconnecting with key.
6. If "bootstrap" — kick off `sshm init <alias>` (which is the same code path as the standalone command).

---

## 8. `sshm ls` Output

```
ID            STATUS  HOST                 USER    AUTH      TAGS              LAST SEEN
aliyun-jiang  ✓ on    203.0.113.10         ming    🔒 key    aliyun, prod      2 min ago
vultr-xray    ✓ on    203.0.113.20         root    🔒 key    vps, proxy        1 hour ago
staging       ✗ off   192.168.1.50         ubuntu  🔒 key    internal          —
github.com    —       ssh.github.com       git     🔒 key    git               —
test-old      ◌ ???   10.0.0.5             root    🔑 pwd    legacy            unknown
```

| Icon | Meaning |
|---|---|
| `✓` green | Reachable, last probe successful |
| `✗` red | Last probe failed |
| `◌` yellow | Unknown / probe never run |
| `—` gray | Excluded from probing (no remote shell; e.g. `github.com`) |
| `🔒` | Key auth |
| `🔑` | Password auth |
| `🤝` | ssh-agent |

Windows `cmd.exe` falls back to `[OK]` / `[X]` / `[?]` / `[--]` when terminal doesn't support unicode (auto-detect; override via `[ui] icons = "ascii"` in config).

---

## 9. AI / MCP Integration

The differentiator. Two complementary layers:

### 9a. `sshm mcp` — built-in MCP server

Started as a stdio subprocess by any MCP-capable host (Claude Code, Cursor, Codex, Gemini CLI).

#### Exposed tools

| Tool | Args | Returns |
|---|---|---|
| `list_servers()` | — | array of `{alias, host (masked), user, tags, last_status}` |
| `get_server(alias)` | `alias` | full record (host masked unless `--reveal`) |
| `add_server(spec, reason)` | TOML-shaped spec + reason | `{alias, needs_copy_id}` |
| `edit_server(alias, patch, reason)` | | updated record |
| `remove_server(alias, reason)` | | ok |
| `test_connection(alias)` | | `{reachable, latency_ms, error?}` |
| `exec(alias, command, timeout?, unsafe?)` | | `{exit, stdout, stderr, duration_ms}` |
| `exec_multi(aliases[], command, timeout?)` | | per-alias result |
| `get_status(alias)` | | uptime / load / mem / disk / listening ports / failed logins |
| `bootstrap(alias, reason)` | | bootstrap report |
| `gen_key(alias, reason)` | | new pubkey content (private key stays local) |
| `copy_id(alias, reason)` | uses keychain or prompts host (NOT model) for password | result |
| `tail_logs(alias, path, n?)` | | log tail |
| `port_forward(alias, spec, reason)` | | forward handle |

#### Safety guarantees (built in, not opt-in)

- **Dangerous command pattern filter**: `exec` rejects commands matching a built-in deny-list unless `unsafe = true` is passed. Patterns include:
  - `rm -rf /`, `rm -rf /*`, `rm -rf ~`
  - `mkfs`, `dd if=… of=/dev/…`
  - `:(){:|:&};:` (fork bomb)
  - `> /dev/sd*`, `chmod -R 000 /`
  - `passwd` interactive without `--stdin`
- **Sensitive data masking** in tool responses: IP → `8.162.*.*`, key path → `<key>`, env values → `***`, passwords never returned.
- **Audit log**: every write tool (`add_server`, `edit_server`, `remove_server`, `exec` with side-effect, `bootstrap`, `copy_id`) writes a line to `~/.config/sshm/audit.log` with timestamp, tool, alias, hash of args, reason, exit code.
- **Reason required** on writes when `[mcp] require_reason = true` (default).
- **No password ever traverses the model**: `copy_id` prompts the local TTY directly or reads from keychain.

### 9b. Claude Code plugin (`sshm-skill`)

A standalone subdirectory `plugins/sshm-skill/` published alongside the binary, packaged into the same GitHub release.

```
plugins/sshm-skill/
├── plugin.json                        # Plugin manifest
├── skills/
│   └── sshm-server-ops/
│       ├── SKILL.md                   # "Use sshm for any server task" guidance
│       ├── quick-reference.md         # Command + MCP-tool cheat sheet
│       └── ai-patterns.md             # Recipes: "deploy a node app", "rotate keys", etc.
├── commands/
│   └── server.md                      # /server slash command wrapper
└── mcp/
    └── sshm-mcp.json                  # Auto-registers `sshm mcp` as MCP server in Claude Code
```

Install in one line once published:

```bash
claude plugins install michael-ltm/sshm
```

---

## 10. Repository Layout

```
sshm/
├── cmd/sshm/                          # main.go, cobra root command
├── internal/
│   ├── config/                        # TOML load/save, migrations
│   ├── ssh/                           # client builder, exec, sftp
│   ├── keys/                          # ed25519 gen + copy-id
│   ├── status/                        # probe + collect
│   ├── bootstrap/                     # embedded init scripts (//go:embed)
│   ├── tui/                           # bubbletea models
│   ├── wizard/                        # huh forms
│   ├── ui/                            # lipgloss styles + icons
│   ├── mcp/                           # MCP server + tool handlers
│   └── safety/                        # dangerous-command + masking + audit
├── plugins/sshm-skill/                # Claude Code plugin (see §9b)
├── scripts/                           # remote-side scripts (bootstrap.sh, status.sh)
├── docs/
│   ├── getting-started.md
│   ├── ai-integration.md
│   ├── security.md
│   ├── specs/                         # this file lives here
│   └── images/                        # GIFs for README
├── .github/workflows/
│   ├── ci.yml                         # test + lint
│   ├── release.yml                    # GoReleaser on tag
│   └── plugin-publish.yml             # publish plugin asset
├── .goreleaser.yaml
├── go.mod
├── README.md                          # screenshots, install, quickstart, AI integration
├── LICENSE                            # MIT
└── CHANGELOG.md                       # Keep-a-Changelog format
```

---

## 11. Distribution

| Platform | Install | Notes |
|---|---|---|
| macOS | `brew install michael-ltm/tap/sshm` | Custom tap repo `homebrew-tap` |
| Linux (deb-based) | `.deb` from Releases or apt repo (later) | GoReleaser builds |
| Linux (rpm-based) | `.rpm` from Releases | GoReleaser builds |
| Linux (any) | `curl -fsSL https://raw.githubusercontent.com/michael-ltm/sshm/main/install.sh \| sh` | One-liner |
| Windows | `scoop bucket add michael-ltm https://github.com/michael-ltm/scoop-bucket && scoop install sshm` | Scoop bucket repo |
| Windows | `winget install michael-ltm.sshm` | (post-launch, requires manifest PR) |
| Go users | `go install github.com/michael-ltm/sshm/cmd/sshm@latest` | |
| Universal | GitHub Releases: tar.gz / zip per OS/arch | linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64 |

---

## 12. Phased Roadmap

| Milestone | Scope | Acceptance |
|---|---|---|
| **v0.1 (MVP)** | TOML config; `ls`, `add` (wizard), `edit`, `rm`, `show`; `c`/`connect`, `exec`; `test` (single + `--all` parallel); `copy-id`; `gen-key`; basic TUI list view; `--json` everywhere; brew + scoop + GitHub Releases via GoReleaser; CI on Win/Mac/Linux | Brand-new user can add a server via wizard, see it green in `sshm ls`, and `sshm c <alias>` into it on Win/Mac/Linux. |
| **v0.2** | `sshm mcp` MCP server with full tool surface from §9a; Claude Code plugin (§9b); `status`; `bootstrap`/`init`; safety filter + masking + audit log | A Claude Code session can `list_servers` → `add_server` → `bootstrap` → `exec` a deploy command, all logged to audit. |
| **v0.3** | `import` / `export` ssh_config; tags + groups view; `exec_multi` w/ prefixed output; `tail_logs`; OS keychain for password auth | Power-user workflow: 20 servers organized by tag, batch run a command across `tag=prod`. |
| **v1.0** | Port forwarding mgmt; SFTP file browse; documentation site; demo GIFs; winget manifest | Public launch on HN / Reddit; README has clear install + first-success in < 60s. |
| **v2+** (deferred) | Cloud provider provisioning (Aliyun/AWS/GCP); session recording; encrypted secrets vault | — |

---

## 13. Error Handling Strategy

- All user-facing errors include: **what failed**, **why (root cause)**, **suggested fix**, **diagnostic command** to run.
- Network/timeout errors distinguish `dns` / `tcp-refused` / `tcp-timeout` / `ssh-handshake` / `auth` and tailor the suggestion.
- TUI never crashes on backend error — it surfaces a red toast and keeps the list usable.
- MCP tool errors return structured JSON: `{error: {kind, message, retriable, suggestion}}`.

---

## 14. Testing Strategy

| Layer | Approach |
|---|---|
| Unit | `testify` table-driven tests on `config`, `safety`, `keys`, masking |
| Integration | Spin up `linuxserver/openssh-server` Docker in CI; assert `ssh.Client` and `exec` end-to-end |
| MCP | Subprocess `sshm mcp`, drive via JSON-RPC harness, assert tool I/O contracts |
| TUI | `bubbletea` test harness — drive key events, snapshot final view |
| Cross-platform | Matrix: `{linux, macos, windows} × {amd64, arm64}` in GitHub Actions |
| Manual smoke | Pre-release checklist run on a real macOS + WSL + native Windows box |

Coverage target: 70% on `internal/`, hard requirement on `safety` and `config`.

---

## 15. Security Considerations

- Configuration file is `chmod 0600` after every write.
- Private keys: never read into memory unless about to be used; never logged; never returned through MCP.
- Audit log includes hash of command, not full command, to avoid leaking secrets.
- `safety` module's deny-list is **opt-out** (`--unsafe` flag / `unsafe: true` MCP arg), never opt-in.
- Output masking is the **default** for MCP responses; opt-in `--reveal` for the local CLI.
- Release artifact signing (cosign / sigstore) is deferred to v1.0 — install scripts will then verify checksums and signatures.

---

## 16. Open Questions / Future Decisions

These intentionally deferred — defaults chosen, revisitable later:

1. Should `sshm export` to `~/.ssh/config` be the default, or opt-in? **Default: opt-in.** Avoids surprise for users with hand-crafted configs.
2. TOML vs JSON for config? **TOML** for now (better human ergonomics). Migration path retained via `version` field.
3. Plugin packaging: separate repo vs monorepo? **Monorepo** under `plugins/sshm-skill/`. Release tooling pulls it into the GitHub Release.
4. Telemetry? **None** in v1. Privacy by default.

---

## 17. Glossary

- **alias** — short identifier for a server, used in all CLI/MCP calls (e.g. `aliyun-jiang`).
- **bootstrap / init** — running `sshm`'s embedded `bootstrap.sh` on the remote to install baseline tooling and harden SSH.
- **probe** — a non-interactive SSH attempt to test reachability, used by `test` and the TUI live status.
- **safety filter** — the pattern matcher in `internal/safety` that gates dangerous commands.

---

## 18. Approval

This document is the source of truth for v0.1–v1.0 scope. Once approved, an implementation plan will be produced via the `superpowers:writing-plans` skill. Any scope change after that point should be reflected here first.
