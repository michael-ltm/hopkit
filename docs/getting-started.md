# Getting Started with sshm

## Install

Pick one — see the README for the full list:

```
brew install michael-ltm/tap/sshm        # macOS / Linux
scoop install sshm                        # Windows
go install github.com/michael-ltm/sshm/cmd/sshm@latest
```

## First server — interactive

```
sshm add
```

The wizard prompts for:

| Field | Notes |
|---|---|
| Alias | lowercase, e.g. `prod-web` |
| Host / IP | DNS name or v4 address |
| Port | default 22 |
| User | unix user on the remote |
| Auth method | existing key / generate / password / agent |
| Tags, Group | optional |
| Test connection after save? | runs a TCP probe and reports |
| Push public key to remote now? | recommended if you have a password |

The new server is written to `~/.config/sshm/config.toml`.

## First server — scripted

```
sshm add --quick prod-web \
  --user ubuntu --host 1.2.3.4 --port 22 \
  -i ~/.ssh/id_ed25519_prod
```

## Daily commands

| Need | Command |
|---|---|
| Show all servers + status | `sshm ls` |
| Connect | `sshm c <alias>` (alias `connect`) |
| One-off command | `sshm exec <alias> 'uptime'` |
| Reachability check | `sshm test <alias>` or `sshm test --all` |
| Install your key on remote | `sshm copy-id <alias>` |
| New key for one host | `sshm gen-key <alias>` |
| Update a field | `sshm edit <alias> --set user=ubuntu` |
| JSON for scripts/AI | append `--json` to any command |

## Config layout

```
version = 2
default = "prod-web"

[servers.prod-web]
host = "1.2.3.4"
port = 22
user = "ubuntu"
auth = "key"
key_path = "~/.ssh/id_ed25519_prod"
tags = ["prod", "aws"]
```

## Troubleshooting

- **`unknown server`** — run `sshm ls` to confirm aliases.
- **`auth=key` but no key_path** — set with `sshm edit <alias> --set key_path=~/.ssh/yourkey`.
- **Connect hangs** — try `sshm test <alias>` first; if it fails, your firewall / proxy is in the way.
