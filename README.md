# sshm

> A pretty, AI-friendly SSH connection manager.
>
> Single binary on Win/Mac/Linux. Pretty `ls` with live status. Wizard `add`. Built-in MCP server for AI assistants (Claude Code, Cursor, Codex, Gemini CLI).

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
sshm download my-host /tmp/app.zip ./app.zip --resume --sha256 <hash>
```

## Features

- TOML config at `~/.config/sshm/config.toml` (XDG) or `%APPDATA%\sshm\config.toml` (Windows)
- `add` (huh wizard) / `edit` / `rm` / `show` / `ls`
- `connect` (interactive shell) / `exec` (one-off) / `test` (single + --all)
- `status` (remote resource snapshot) / `init` (baseline hardening)
- `gen-key` (ed25519) / `copy-id` (one-shot password, never stored)
- `upload` / `download` (single-file SFTP with `.part`, resume, SHA-256)
- **`mcp` — built-in MCP server** so AI assistants (Claude Code, Cursor,
  Codex, Gemini CLI) can manage your servers — including layered SSH checks,
  background file transfer (`transfer_start`/`transfer_status`) and host-key
  verification (TOFU). See [docs/ai-integration.md](docs/ai-integration.md).
- `--json` on every command for scripting and AI integration
- Pretty list with unicode/ascii icons (auto-detected)
- Proxy/jump-host connections: per-host SOCKS5 (`proxy`), ProxyJump (`proxy_jump`), ProxyCommand (`proxy_command`); SOCKS5 auto-detected from `ALL_PROXY`/`HTTPS_PROXY` env vars (zero-config); failed proxy attempts fall back to direct

## AI integration

```
claude plugins marketplace add michael-ltm/sshm
claude plugins install sshm-skill@sshm
```

Then ask your assistant to "check the status of my prod server" or "deploy
the latest code to staging". sshm's MCP tools are audited, mask secrets, and
block dangerous commands. See [docs/ai-integration.md](docs/ai-integration.md)
and [docs/security.md](docs/security.md).

## Roadmap

- **v0.3** ✓ — Host-key TOFU verification (strict known_hosts still v1.0), parallel `exec_multi`, `upload`/`download` single files, `exec` timeout + detach — _shipped_
- **v0.4** ✓ — Proxy/VPN-aware dialing: SOCKS5 (`proxy`), ProxyJump, ProxyCommand; SOCKS5 auto-detected from env; automatic direct fallback — _shipped_
- **v0.5** ✓ — Secure key provisioning, encrypted key support, large-transfer-safe MCP/CLI file transfer — _shipped_
- **v0.6** — Import/export `~/.ssh/config`, tags/groups
- **v1.0** — Port forwarding, SFTP browse, signed release artifacts, strict known_hosts enforcement

See [docs/specs/2026-05-13-sshm-design.md](docs/specs/2026-05-13-sshm-design.md) for the full design.

## Release Process (maintainers)

Releases are automated by GoReleaser on tag push:

```
git tag v0.1.0 && git push origin v0.1.0
```

Required repo secrets: `HOMEBREW_TAP_TOKEN`, `SCOOP_BUCKET_TOKEN` — PATs with `contents:write` on `homebrew-tap` and `scoop-bucket`.

## License

MIT — see [LICENSE](LICENSE).
