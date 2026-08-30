# Getting Started with sshm

## Install

Pick one — see the README for the full list:

```
brew install michael-ltm/tap/sshm        # macOS / Linux
scoop install sshm                        # Windows
go install github.com/michael-ltm/sshm/cmd/sshm@latest
```

## First server — guided one-line pairing (recommended)

Run the guided command on the controller. You do not need to know the remote
username first:

```
sshm pair
```

The wizard asks for an alias, host/IP, SSH port, target system (Windows, Linux,
macOS, or unsure), description, tags, and group. Windows is the default choice.
Keep sshm running after the form completes, then paste the single printed line
into Administrator PowerShell on Windows or a shell on Linux/macOS. The target
checks OpenSSH, installs/starts it if necessary, adds the generated public key,
reports its actual username, and then the controller proves key authentication
by running `whoami` and `hostname`. Only that verified result is saved.

Paste the generated line exactly as printed; the Linux/macOS command invokes
`sudo` itself only when a privileged step needs it. Its compressed payload is
decoded into a private temporary file and must pass both gzip integrity and
shell-syntax checks before any setup step runs. An incomplete clipboard copy
therefore stops with a clear regeneration message instead of executing a
partial script.

Before any target command is printed, sshm also proves that the selected local
private key can actually sign through the current keychain/ssh-agent. If an
encrypted key is locked or the agent is unavailable, pairing stops locally and
prints recovery steps; nothing has been changed on the target yet.

The flag form remains available for scripts and experienced users:

```
sshm pair office-pc --host 100.64.0.10 --target windows \
  --description "Windows office workstation" \
  --tags windows,office --group workstations
```

For an alias already in sshm, use `sshm pair <alias>`. Existing host and port
values are preserved; change them explicitly with `sshm edit` first. Pairing
does not disable password login. The generated key is encrypted by default;
keep the printed recovery-file path safe.

The target must be able to reach the controller over a private LAN or
Tailscale address for the one-time callback. sshm rejects automatically
detected public/TUN routes and manually entered public IP literals. A manually
entered hostname is also rejected when local DNS resolves it to any public or
TUN fake address. IPv6 link-local callback addresses (`fe80::/10`, including
zone-qualified forms such as `%en0`) are also rejected because the generated
cross-platform command cannot preserve interface scope reliably; use a ULA,
Tailscale address, LAN IPv4 address, or private hostname instead. An unresolved
MagicDNS/LAN name is ultimately resolved by the target. If
automatic route selection is wrong, enter a
target-reachable private address when the wizard asks for it. In scripted mode,
pass the same address with `--callback-host <ip>`.

On Windows, the target command tries the built-in OpenSSH Server capability
first. If Windows Update or the capability source is unavailable, it retries
several download mechanisms and can use a previously downloaded official ZIP:

```powershell
$env:SSHM_OPENSSH_ZIP='D:\Installers\OpenSSH-Win64.zip'
# Paste the same sshm-generated one-line command after setting the variable.
```

When this variable is set and `sshd` is absent, pairing skips the potentially
slow online Windows Capability attempt and goes straight to the verified local ZIP.
The offline ZIP must match the architecture and the version pinned by that
sshm build; its whole-file SHA-256 is verified before extraction, and `sshd.exe`
must also have a valid Microsoft signature. Existing OpenSSH installations are
not silently rewritten to a different port: if their effective port does not
match the address recorded in sshm, the command stops with a repair instruction.
The controller waits 30 minutes by default for slower Windows capability or
fallback installs; scripted users can override this with `--timeout`.

Windows pairing supports local accounts and traditional Active Directory
accounts. Microsoft Entra/AzureAD account authentication is not supported by
Windows OpenSSH; run the command from a local or AD login account instead.

## Add menu and advanced manual entry

```
sshm add
```

First choose **One-line automatic pairing (recommended)** or **Manual record
(SSH already configured)**. Automatic pairing opens the same guided flow as
plain `sshm pair`. Manual entry prompts for:

| Field | Notes |
|---|---|
| Alias | lowercase, e.g. `prod-web` |
| Host / IP | DNS name or v4 address |
| Port | default 22 |
| Target system | Windows, Linux, or macOS; Windows is the default |
| User | unix user on the remote |
| Auth method | existing key / generate / password / agent |
| Description | purpose, OS/tooling, and constraints; used by humans and AI to choose a host |
| Tags, Group | optional capability and organization metadata |
| Test connection after save? | runs a TCP probe and reports |
| Show the copy-id next step? | available for key auth; the next command prompts for the password once |

The new server is written to `~/.config/sshm/config.toml`.

## First server — scripted

```
sshm add --quick prod-web \
  --user ubuntu --host 1.2.3.4 --port 22 \
  -i ~/.ssh/id_ed25519_prod \
  --description "Linux production web server; Docker; deploy only" \
  --tags linux,production,docker --group production
```

## Daily commands

| Need | Command |
|---|---|
| Browse/select/manage servers | `sshm list` (↑/↓, Enter, `/` to filter) |
| Print all servers as a table | `sshm ls --plain` |
| Pair a new machine with a guided form | `sshm pair` |
| Advanced/scripted pairing | `sshm pair <alias> --host <host> --target windows\|posix` |
| Repair/pair an existing alias | `sshm pair <alias>` |
| Connect | `sshm c <alias>` (alias `connect`) |
| One-off command | `sshm exec <alias> 'uptime'` |
| Direct TCP reachability check | `sshm test <alias>` or `sshm test --all` |
| Install your key on remote | `sshm copy-id <alias>` |
| New key for one host | `sshm gen-key <alias>` |
| Update a field | `sshm edit <alias> --set user=ubuntu` |
| Add/update a description | `sshm edit <alias> --set description="Windows x64 reverse lab; CDB"` |
| Change remote login password | `sshm password <alias>` (terminal only; exact-alias confirmation) |
| Review unused server records | `sshm cleanup` (safe guided selection) |
| Preview cleanup without deleting | `sshm cleanup --plain` or `sshm cleanup --json` |
| JSON for scripts/AI | append `--json` where the command supports structured output |
| Share-safe JSON | append `--json --redacted` (exact JSON remains available to trusted scripts) |

## Config layout

```
version = 5
default = "prod-web"

[servers.prod-web]
host = "1.2.3.4"
port = 22
user = "ubuntu"
auth = "key"
key_path = "~/.ssh/id_ed25519_prod"
platform = "linux"
description = "Linux production web server; Docker; deploy only"
tags = ["prod", "aws"]
created_at = 2026-08-29T08:00:00Z
last_used = 2026-08-29T09:30:00Z
last_seen = 2026-08-29T09:30:00Z
last_checked = 2026-08-29T09:30:00Z
```

`last_used` means sshm observed a successful SSH authentication through one of
its own CLI/MCP operations; SSH sessions opened directly by another client are
not visible to sshm. `last_seen` means the host was most recently confirmed
reachable, while `last_checked` also advances after a failed reachability test.
A TCP probe never counts as new SSH use. During a version-4 migration, an
existing legacy `last_seen` value is conservatively copied to `last_used` so an
upgrade cannot suddenly offer a previously active record for cleanup. Version-4
records with no timestamps are shown as **history unknown** and are excluded
from cleanup unless you explicitly include them.

Changing `host`, `port`, or `user` with `sshm edit` resets the old target's
activity timestamps and starts a fresh cleanup baseline at the identity-change
time; the original creation date is still retained. Changing descriptions,
tags, platform, or other metadata does not reset history. If an SSH login
succeeds but the timestamp cannot be written, sshm keeps the session usable and
prints an explicit warning instead of silently leaving cleanup history stale.

## Cleaning old records

Run `sshm cleanup` to choose an age rule and select records. Nothing is selected
by default, and a final confirmation is required. sshm automatically protects
the default server, project-profile references, ProxyJump references, and
records marked with `cleanup_protected = true`. Before removal it writes a
private config backup (`0600` on macOS/Linux and a current-user/LocalSystem ACL
on Windows).

Cleanup removes only selected entries from sshm's config. It does not delete
private keys, `known_hosts` entries, or public keys installed on remote
machines. Use `--include-unknown` only when you intentionally want legacy
records with no activity history to appear as candidates.

## Troubleshooting

- **`unknown server`** — run `sshm ls` to confirm aliases.
- **`auth=key` but no key_path** — set with `sshm edit <alias> --set key_path=~/.ssh/yourkey`.
- **Connect hangs** — `sshm test <alias>` checks the direct TCP route only. For a proxy/ProxyJump host, use a real `sshm exec` or MCP `check_ssh`; a failed direct probe does not prove the proxied SSH route is down.
- **Pairing rejects the detected callback address** — TUN fake-IP/public routes
  and IPv6 link-local addresses are intentionally rejected. The interactive
  flow asks for a private LAN/Tailscale address reachable from the target;
  scripted mode uses `--callback-host`.
- **Windows cannot download OpenSSH** — download the architecture-matching ZIP
  from the official Win32-OpenSSH release on another connection, set
  `SSHM_OPENSSH_ZIP` to that local file, then paste the same generated command.
- **Pairing stops before printing a target command** — start/unlock your
  keychain or ssh-agent and load the named key with `ssh-add`; sshm deliberately
  refuses to install a public key that it cannot use for the final login proof.
- **`pairing command is incomplete or corrupted`** — discard that one-time
  command and rerun pairing, then copy the complete newly generated line. If a
  terminal or chat bridge still truncates long lines, use `--script-dir` and
  transfer the protected command file instead of copying rendered output.
- **Pair command times out** — leave the generated key in place, fix the
  controller callback/firewall route, then follow the printed retry guidance.
  For a not-yet-saved alias, rerun plain `sshm pair` and enter the same alias
  and address; sshm reuses the generated key. For an existing record, rerun
  `sshm pair <alias>`.
