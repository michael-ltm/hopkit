package ssh

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// Only augment shells whose syntax is known. Windows retains native CMD or
// PowerShell semantics; unknown custom shells keep their original environment. Login profiles run only as their owning SSH user;
// no desktop credential variables or keychain secrets are copied into SSH.
const shellProbe = `printf 'SSHM_SHELL=%s\n' "$SHELL"`

const userPathPrefix = `for sshm_exec_path in /opt/homebrew/bin /opt/homebrew/sbin /usr/local/bin /usr/local/sbin /home/linuxbrew/.linuxbrew/bin "$HOME/.linuxbrew/bin" "$HOME/.local/bin" "$HOME/bin" "$HOME/.cargo/bin" "$HOME/.pyenv/shims" "$HOME/.asdf/shims" "$HOME/.local/share/mise/shims" "$HOME/.volta/bin" /opt/local/bin /snap/bin; do
 if [ -d "$sshm_exec_path" ]; then
  case ":$PATH:" in *":$sshm_exec_path:"*) ;; *) PATH="${PATH:+$PATH:}$sshm_exec_path" ;; esac
 fi
done
export PATH
unset sshm_exec_path
# nvm is normally initialized only in interactive rc files. Load the owning
# user's default only when no node is already selected; never guess a version.
if ! command -v node >/dev/null 2>&1 && [ -r "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]; then
 . "${NVM_DIR:-$HOME/.nvm}/nvm.sh" >/dev/null 2>&1
fi
`

func userShell(output string) string {
	for _, line := range strings.Split(output, "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "SSHM_SHELL=")
		if !ok || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, " \t\r") {
			continue
		}
		switch path.Base(value) {
		case "sh", "bash", "zsh", "dash", "ksh":
			return value
		}
	}
	return ""
}
func supportedUserShell(output string) bool { return userShell(output) != "" }
func loginUserCommand(shell, command string) string {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	return quote(shell) + " -lc " + quote(userPathPrefix+command)
}

// desktopUserCommand delegates only after the user has explicitly enabled
// their own desktop agent. exec replaces the SSH child, so disconnect/kill
// closes the private socket and cancels its command. No retry after dispatch.
func desktopUserCommand(shell, command string) string {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	dispatch := `if [ "$(uname -s)" = Darwin ] && [ -f "$HOME/Library/Application Support/sshm/desktop/enabled" ]; then
 if ! command -v sshm >/dev/null 2>&1; then
  printf '%s\n' 'Desktop execution is enabled but sshm is unavailable in PATH; command was not run.' >&2
  exit 69
 fi
 exec sshm desktop exec -- ` + quote(userPathPrefix+command) + `
fi
`
	return loginUserCommand(shell, dispatch+command)
}

// PrepareUserCommand preserves existing PATH precedence, adding only missing
// conventional installation directories after loading the user login shell. Raw Exec stays available for protocol
// probes and callers requiring the exact sshd environment.
func (c *Client) PrepareUserCommand(ctx context.Context, command string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := c.Exec(probeCtx, shellProbe)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("inspect remote execution environment: %w", err)
	}
	if res.ExitCode == 0 && supportedUserShell(res.Stdout) {
		return desktopUserCommand(userShell(res.Stdout), command), nil
	}
	win, err := c.Exec(probeCtx, "cmd /c ver")
	if err != nil {
		return "", fmt.Errorf("inspect native shell: %w", err)
	}
	if strings.Contains(strings.ToLower(win.Stdout), "windows") {
		which, err := c.Exec(probeCtx, "echo %COMSPEC%")
		if err != nil {
			return "", err
		}
		text := strings.ToLower(strings.TrimSpace(which.Stdout))
		if strings.HasSuffix(text, "cmd.exe") {
			return windowsUserCommand(command, true), nil
		}
		// In PowerShell the CMD expansion is a literal. Confirm the shell before
		// interpreting caller commands as PowerShell.
		ps, err := c.Exec(probeCtx, "$PSVersionTable.PSEdition")
		if err != nil {
			return "", err
		}
		edition := strings.TrimSpace(ps.Stdout)
		if edition == "Desktop" {
			return windowsUserCommand(command, false), nil
		}
		if edition == "Core" {
			return strings.Replace(windowsUserCommand(command, false), "powershell.exe ", "pwsh.exe ", 1), nil
		}
	}
	return command, nil
}

func (c *Client) ExecUser(ctx context.Context, command string) (*ExecResult, error) {
	prepared, err := c.PrepareUserCommand(ctx, command)
	if err != nil {
		return &ExecResult{ExitCode: -1}, err
	}
	return c.Exec(ctx, prepared)
}

func (c *Client) StreamExecUser(ctx context.Context, command string, stdout, stderr io.Writer) (int, error) {
	prepared, err := c.PrepareUserCommand(ctx, command)
	if err != nil {
		return -1, err
	}
	return c.StreamExec(ctx, prepared, stdout, stderr)
}
