# Changelog

All notable changes to this project will be documented in this file. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- Plugin distribution: the repo now has a proper `.claude-plugin/marketplace.json` so `claude plugins marketplace add michael-ltm/sshm` works. The plugin manifest moved to `.claude-plugin/plugin.json` and the MCP registration to `.mcp.json` per the Claude Code plugin format.

## [0.2.0]

### Added
- `sshm mcp` — built-in MCP server exposing 13 tools for AI assistants.
- `sshm status` — remote resource snapshot (uptime, load, memory, disk).
- `sshm init` — baseline server hardening (installs fail2ban, reports sshd state).
- `internal/safety` — dangerous-command filter, secret masking, audit log.
- Claude Code plugin `sshm-skill` (install: `claude plugins marketplace add michael-ltm/sshm` then `claude plugins install sshm-skill@sshm`).
- `docs/ai-integration.md`, `docs/security.md`.

## [0.1.0]

### Added
- Initial project scaffold.
