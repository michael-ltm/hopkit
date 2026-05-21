# sshm

> A pretty, AI-friendly SSH connection manager.
>
> Single binary on Win/Mac/Linux. Pretty `ls` with live status. Wizard `add`. Built-in MCP server for AI assistants (Claude Code, Cursor, Codex, Gemini CLI) — coming in v0.2.

## Install

| Platform | Command |
|---|---|
| macOS / Linux (Homebrew) | `brew install michael-ltm/tap/sshm` |
| Windows (Scoop) | `scoop bucket add michael-ltm https://github.com/michael-ltm/scoop-bucket && scoop install sshm` |
| Anywhere (Go) | `go install github.com/michael-ltm/sshm/cmd/sshm@latest` |
| Direct download | [GitHub Releases](https://github.com/michael-ltm/sshm/releases) — tar.gz / zip per OS+arch |

## Quickstart

```
sshm add               # interactive wizard
sshm ls                # see all servers + status
sshm c my-host         # interactive shell
sshm exec my-host 'uptime'
sshm test --all        # parallel reachability check
```

## Features (v0.1)

- TOML config at `~/.config/sshm/config.toml` (XDG) or `%APPDATA%\sshm\config.toml` (Windows)
- `add` (huh wizard) / `edit` / `rm` / `show` / `ls`
- `connect` (interactive shell) / `exec` (one-off) / `test` (single + --all)
- `gen-key` (ed25519) / `copy-id` (one-shot password, never stored)
- `--json` on every command for scripting and AI integration
- Pretty list with unicode/ascii icons (auto-detected)

## Roadmap

- **v0.2** — Built-in MCP server (`sshm mcp`) + Claude Code plugin + safety filter + bootstrap/init
- **v0.3** — Import/export `~/.ssh/config`, tags/groups, parallel exec, OS keychain
- **v1.0** — Port forwarding, SFTP browse, signed release artifacts, demo site

See [docs/specs/2026-05-13-sshm-design.md](docs/specs/2026-05-13-sshm-design.md) for the full design.

## Release Process (maintainers)

Releases are automated by GoReleaser on tag push:

```
git tag v0.1.0 && git push origin v0.1.0
```

Required repo secrets: `HOMEBREW_TAP_TOKEN`, `SCOOP_BUCKET_TOKEN` — PATs with `contents:write` on `homebrew-tap` and `scoop-bucket`.

## License

MIT — see [LICENSE](LICENSE).
