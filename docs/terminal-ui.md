# Terminal workspace

Run `sshm` or `sshm list` in a terminal. A wide window shows the selected
server's connection, group, tags and last observed status beside the list.
Narrow windows collapse the details pane and keep the selected row in view.
Status marks describe saved observations, not continuous live monitoring.

The top bar distinguishes the local inventory from an optional cloud account.
It shows the account saved on this device; it does not unlock the cloud vault
or silently replace local servers with cloud records.

| Key | Action |
| --- | --- |
| Up / Down, j / k | Move through servers |
| Page Up / Page Down, Ctrl+U / Ctrl+D | Move one page |
| Home / End | First / last result |
| / | Search names, hosts, users, descriptions, groups and tags |
| Enter while searching | Finish editing the search; keep filtered results |
| Enter on a server | Open its existing management menu |
| c | Connect to the selected server |
| g | Cycle available groups |
| s | Toggle alphabetical / recent-use sorting |
| a | Add or pair a server |
| r | Reload the local inventory |
| x | Review unused servers in the existing cleanup wizard |
| ? | Toggle the shortcut reminder |
| Escape | Finish search, clear a filter, or leave the browser |
| q / Ctrl+C | Leave the browser; q remains ordinary text during search |

Search is case-insensitive and matches every entered word. Pasting text starts
searching instead of executing shortcut letters. Browsing and filtering do not
change configuration or contact servers. Existing confirmations still apply to
removal, password changes and other consequential operations.

The interface uses standard terminal characters, with ASCII chrome when
`ui.icons = "ascii"` or automatic legacy-terminal detection selects ASCII.
It supports light and dark terminal backgrounds and honors `NO_COLOR`;
`--no-color` removes styling from the browser. No Nerd Font is required.

`sshm list --json`, MCP and existing noninteractive commands keep their original
interfaces. `sshm list --plain` prints the existing table. Bare `sshm` outside a
terminal prints help rather than opening a UI.

Verification: model tests cover 50-entry scrolling, resizing down to tiny
windows, Chinese display widths, search/shortcut separation, ASCII and terminal
escape sanitization. macOS PTY tests exercise 120x30, 80x24 and 40x12 windows,
search edits and restoration of the alternate screen. Separate native process
tests use disposable configurations to verify keyboard events and JSON output.

Release `0.8.0-cloud-preview.8` was installed through the signed updater on the
local Mac, Mac mini, GrokBot and att-dev; each device's before/after server list
matched. macOS and Linux native process tests passed. Windows ConPTY tests
passed at 120x30, 80x24 and 40x12 with search, shortcut isolation, clean exit and
unchanged fixture files. Direct pipe-based TUI input is not a replacement for
a Windows console; JSON/noninteractive commands remain suitable for pipes.

Download builds cover amd64 and arm64 for all three operating systems. Native
runtime testing used the four available machines (macOS arm64, Linux amd64,
Windows amd64); the other architecture variants were cross-compiled. The
preview image is rendered from macOS PTY output using a synthetic inventory,
not a screenshot of a user's private Terminal window.

## Recent SSH use and TCP latency

The list now includes `LAST SSH` (for example `3m ago`, `2h ago`, `5d ago`).
This is the last successful authenticated SSH use recorded by SSHM, including
CLI and MCP connections; opening the list or probing does not reset it.
A dash means no recorded use. Relative times refresh while the list stays open.

Press `p` to probe the currently filtered servers, with at most six connections
in flight and a three-second deadline per target. Search, scrolling and quitting
remain available. Results are TCP connection time in milliseconds, **not**
bandwidth or an SSH authentication check. DNS and the current network route can
contribute to the measurement. Configured jump/proxy routes show `via route`
instead of measuring an unrelated direct connection. `no reply` means the TCP
attempt failed; it does not prove the device is powered off. Results stay in
memory for this browser session and do not replace saved status observations.

The `a` action presents one Add server entry with automatic setup and an existing
SSH login option. Port 22 is the default on all platforms. Custom port,
description, group and tags are optional advanced settings. Windows guided
setup now generates a readable script and a companion launcher; see
[Windows pairing](windows-pairing.md).

From `0.8.0-cloud-preview.8`, the running version remains visible even in narrow
windows. When a signed newer release is available, the inventory first offers
Update now / Skip for now (default Skip). Update reopens the new inventory;
Skip continues the current version. See the update details in
[cloud-sync.md](cloud-sync.md#interactive-update-choices-preview8).


## Home (preview.26)

Run `sshm` to open Home, `s` for the recent-first server list, `y` for sync,
`l` for account/login/logout, `u` for signed update review, `,` for settings,
and `q` to exit without logging out. Arrow keys and Enter also work. Esc returns
from submenus. Home and the server browser support English and Simplified Chinese;
legacy command output and some onboarding prompts remain English.

Home also exposes adding ordinary SSH hosts, selecting existing account devices
to add to the vault, enabling this device, and Codex/Claude integration status.
Device entries omit inapplicable SSH repair, password and TCP probe actions.
Original commands are grouped in help rather than deleted, preserving scripts,
MCP and hosts without an SSHM agent. `sshm settings --language zh-CN` selects Chinese
without a form; `--language en` or `auto` switches back. Numeric counts do not
include credentials; cloud count is an explicit historical snapshot, never a
claim that a locked vault was read live.

In preview.29, UI preferences use `config.toml.ui.json` so older agent writes cannot reset the language. Cloud bindings use a separate index; unresolved cloud references are shown as needing sync instead of being counted as local-only.
