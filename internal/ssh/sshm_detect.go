package ssh

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"github.com/michael-ltm/sshm/internal/config"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

var detectedVersion = regexp.MustCompile(`(?m)^(?:sshm\s+(?:version\s+)?)?v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?)\s*$`)

func installationOutput(out string, err error) (string, string) {
	if err != nil {
		return "unknown", ""
	}
	if strings.TrimSpace(out) == "SSHM_NOT_INSTALLED" {
		return "missing", ""
	}
	if match := detectedVersion.FindStringSubmatch(out); len(match) == 2 {
		return "installed", match[1]
	}
	if strings.HasPrefix(out, "SSHM_INSTALLED\n") {
		return "installed", ""
	}
	return "unknown", ""
}

// DetectSSHM checks PATH and documented user/system installation locations.
// Failure to authenticate or run the check is not evidence of an absent client.
func (c *Client) DetectSSHM(ctx context.Context, platform string) (string, string) {
	command := `p=$(command -v sshm 2>/dev/null || true); if [ -z "$p" ]; then for f in "$HOME/.local/bin/sshm" "$HOME/.cargo/bin/sshm" /opt/homebrew/bin/sshm /usr/local/bin/sshm; do if [ -x "$f" ]; then p="$f"; break; fi; done; fi; if [ -n "$p" ]; then printf 'SSHM_INSTALLED\n'; "$p" version; else printf 'SSHM_NOT_INSTALLED\n'; fi`
	if platform == config.PlatformWindows {
		script := `$p=(Get-Command sshm.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source; if (-not $p) { foreach ($f in @("$env:USERPROFILE\.local\bin\sshm.exe","$env:USERPROFILE\.cargo\bin\sshm.exe","$env:USERPROFILE\sshm\sshm.exe")) { if (Test-Path -LiteralPath $f -PathType Leaf) { $p=$f;break } } }; if ($p) { Write-Output 'SSHM_INSTALLED'; & $p version } else { Write-Output 'SSHM_NOT_INSTALLED' }`
		code := utf16.Encode([]rune(script))
		raw := make([]byte, len(code)*2)
		for i, v := range code {
			binary.LittleEndian.PutUint16(raw[i*2:], v)
		}
		command = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(raw)
	} else if platform != "linux" && platform != "macos" {
		return "unknown", ""
	}
	out, err := c.platformCommand(ctx, command)
	return installationOutput(strings.ReplaceAll(out, "\r\n", "\n"), err)
}
func RecordSSHM(path, alias string, expected *config.Server, status, version string, at time.Time) error {
	return config.Update(path, func(cfg *config.Config) error {
		s := cfg.Servers[alias]
		if s == nil || expected == nil || s.Host != expected.Host || s.Port != expected.Port || s.User != expected.User {
			return nil
		}
		if !at.Before(s.SSHMCheckedAt) {
			s.SSHMStatus = status
			s.SSHMVersion = version
			s.SSHMCheckedAt = at.UTC()
		}
		return nil
	})
}
