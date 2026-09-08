package ssh

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf16"
)

// EnvironmentReport describes this process/session only. Authentication failures
// are deliberately not classified as logout: keychains, network, SSO, scopes,
// credential helpers and the selected OS user can all differ from a desktop.
type EnvironmentReport struct {
	ExecutionContext string            `json:"execution_context"`
	Scope            string            `json:"scope"`
	Platform         string            `json:"platform"`
	User             string            `json:"os_user,omitempty"`
	GHOriginalPath   string            `json:"gh_original_path,omitempty"`
	GHEffectivePath  string            `json:"gh_effective_path,omitempty"`
	Tools            map[string]string `json:"tools"`
	GitPath          string            `json:"git_path,omitempty"`
	GitHub           string            `json:"github_access"`
	Account          string            `json:"github_account,omitempty"`
	Note             string            `json:"note"`
}

const environmentNote = "Only this execution session was checked. CLI discovery, GitHub API authorization and Git credential-helper access are separate. Unavailable access does not prove logout or an invalid stored token; check the OS user, keychain/session access, network and account selection before re-authenticating."

const posixEnvironmentCheck = `printf 'platform\t%s\n' "$(uname -s)"
printf 'execution_context\t%s\n' "${SSHM_EXECUTION_CONTEXT:-ssh_or_local}"
printf 'user\t%s\n' "$(id -un)"
printf 'gh_original\t%s\n' "$(command -v gh 2>/dev/null)"
` + userPathPrefix + `printf 'gh_effective\t%s\n' "$(command -v gh 2>/dev/null)"
printf 'git\t%s\n' "$(command -v git 2>/dev/null)"
for sshm_check_tool in node npm python python3; do
 printf 'tool_%s\t%s\n' "$sshm_check_tool" "$(command -v "$sshm_check_tool" 2>/dev/null)"
done
if command -v gh >/dev/null 2>&1; then
 if sshm_check_account=$(GH_PROMPT_DISABLED=1 gh api --hostname github.com user --jq .login 2>/dev/null); then
  printf 'github\tverified\naccount\t%s\n' "$sshm_check_account"
 else
  printf 'github\tunavailable_in_session\n'
 fi
else
 printf 'github\tcli_not_found\n'
fi
`

const windowsEnvironmentCheck = `$ErrorActionPreference = 'Stop'
$tab = [char]9
Write-Output ("user" + $tab + [Environment]::UserName)
$gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$git = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Output ("git" + $tab + $git.Source)
foreach ($name in @('node','npm','python','python3')) {
 $tool = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
 Write-Output ("tool_" + $name + $tab + $tool.Source)
}
if ($gh) {
 Write-Output ("gh_original" + $tab + $gh.Source)
 Write-Output ("gh_effective" + $tab + $gh.Source)
 $env:GH_PROMPT_DISABLED = '1'
 $ErrorActionPreference = 'Continue'
 $account = & $gh.Source api --hostname github.com user --jq .login 2>$null
 if ($LASTEXITCODE -eq 0) { Write-Output ("github" + $tab + "verified"); Write-Output ("account" + $tab + $account) }
 else { Write-Output ("github" + $tab + "unavailable_in_session") }
} else { Write-Output ("github" + $tab + "cli_not_found") }
`

func encodeEnvironmentPowerShell(script string) string {
	words := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[i*2:], w)
	}
	return "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(b)
}

func parseEnvironmentReport(output, scope, platform string) EnvironmentReport {
	r := EnvironmentReport{Scope: scope, Platform: platform, GitHub: "unknown", Note: environmentNote, Tools: map[string]string{}}
	for _, line := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "\t")
		if !ok {
			continue
		}
		switch k {
		case "tool_node", "tool_npm", "tool_python", "tool_python3":
			r.Tools[strings.TrimPrefix(k, "tool_")] = v
		case "execution_context":
			if v == "desktop_user" {
				r.ExecutionContext = v
			}
		case "platform":
			switch v {
			case "Darwin":
				r.Platform = "darwin"
			case "Linux":
				r.Platform = "linux"
			}
		case "user":
			r.User = v
		case "gh_original":
			r.GHOriginalPath = v
		case "gh_effective":
			r.GHEffectivePath = v
		case "git":
			r.GitPath = v
		case "github":
			switch v {
			case "verified", "unavailable_in_session", "cli_not_found":
				r.GitHub = v
			}
		case "account":
			// GitHub usernames have only ASCII letters, digits and hyphens. Reject
			// unexpected stdout rather than returning arbitrary CLI output as identity.
			if len(v) > 0 && len(v) <= 39 && strings.Trim(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") == "" {
				r.Account = v
			}
		}
	}
	if r.ExecutionContext == "" {
		r.ExecutionContext = scope
	}
	if r.GitHub != "verified" {
		r.Account = ""
	}
	return r
}

func (c *Client) CheckEnvironment(ctx context.Context) (*EnvironmentReport, error) {
	res, err := c.Exec(ctx, shellProbe)
	if err != nil {
		return nil, err
	}
	platform, command := "posix", posixEnvironmentCheck
	originalGH := ""
	if res.ExitCode != 0 || !supportedUserShell(res.Stdout) {
		win, err := c.Exec(ctx, "cmd /c ver")
		if err != nil {
			return nil, err
		}
		if !strings.Contains(strings.ToLower(win.Stdout), "windows") {
			return nil, fmt.Errorf("unsupported remote shell; inspect its native PATH and credentials without assuming logout")
		}
		platform, command = "windows", encodeEnvironmentPowerShell(windowsPathPrefix+windowsEnvironmentCheck)
	}
	if platform == "posix" {
		original, e := c.Exec(ctx, "command -v gh")
		if e != nil {
			return nil, e
		}
		if original.ExitCode == 0 {
			originalGH = strings.TrimSpace(original.Stdout)
		}
		command, err = c.PrepareUserCommand(ctx, command)
		if err != nil {
			return nil, err
		}
	}
	res, err = c.Exec(ctx, command)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("environment probe failed (exit %d); authentication state is unknown", res.ExitCode)
	}
	r := parseEnvironmentReport(res.Stdout, "remote_ssh", platform)
	if platform == "posix" {
		r.GHOriginalPath = originalGH
	}
	return &r, nil
}

func CheckLocalEnvironment(ctx context.Context) (*EnvironmentReport, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		encoded := strings.Fields(encodeEnvironmentPowerShell(windowsPathPrefix + windowsEnvironmentCheck))
		cmd = exec.CommandContext(ctx, encoded[0], encoded[1:]...)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", posixEnvironmentCheck)
	}
	// Stderr is deliberately discarded; never expose gh auth/token diagnostics.
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("local environment probe failed; authorization is unknown: %w", err)
	}
	r := parseEnvironmentReport(string(out), "local_process", runtime.GOOS)
	return &r, nil
}
