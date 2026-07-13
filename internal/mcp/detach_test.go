package mcp

import (
	"encoding/base64"
	"encoding/binary"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func TestBuildDetachLauncherUsesNestedEncodedCommandsForWindows(t *testing.T) {
	command := "$source = 'C:\\Build Root\\app source'\r\n$payload = @'\r\nchild data\r\n'@\r\nWrite-Output first; Write-Output second\r\n# trailing comment"
	launcher := buildDetachLauncher("windows", command, 123)

	const prefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
	require.True(t, strings.HasPrefix(launcher.Command, prefix))
	require.NotContains(t, launcher.Command, command)
	require.NotContains(t, launcher.Command, "$script=")
	require.NotContains(t, launcher.Command, "Start-Process")

	encoded := strings.TrimPrefix(launcher.Command, prefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.Zero(t, len(decoded)%2)
	words := make([]uint16, len(decoded)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(decoded[i*2:])
	}
	outerScript := string(utf16.Decode(words))
	require.Contains(t, outerScript, "Start-Process")
	require.Contains(t, outerScript, "'-EncodedCommand',$childEncoded")
	require.Contains(t, outerScript, "Write-Output ('pid=' + $p.Id)")
	require.Contains(t, outerScript, "Write-Output ('log=' + $log)")
	require.NotContains(t, outerScript, "'-File'")
	require.NotContains(t, outerScript, "Set-Content")
	require.NotContains(t, outerScript, "sshm-detach-123.ps1")
	require.NotContains(t, outerScript, command)
	require.NotContains(t, outerScript, "\n'@\n")
	require.NotContains(t, outerScript, `C:\Build Root\app source`)

	match := regexp.MustCompile(`\$childEncoded='([A-Za-z0-9+/=]+)'`).FindStringSubmatch(outerScript)
	require.Len(t, match, 2)
	innerBytes, err := base64.StdEncoding.DecodeString(match[1])
	require.NoError(t, err)
	require.Zero(t, len(innerBytes)%2)
	innerWords := make([]uint16, len(innerBytes)/2)
	for i := range innerWords {
		innerWords[i] = binary.LittleEndian.Uint16(innerBytes[i*2:])
	}
	innerScript := string(utf16.Decode(innerWords))
	normalizedCommand := strings.ReplaceAll(command, "\r\n", "\n")
	require.Equal(t, "& {\n"+normalizedCommand+"\n} *> (Join-Path $env:TEMP 'sshm-detach-123.log')", innerScript)
	require.Contains(t, innerScript, "Write-Output first; Write-Output second")
	require.Contains(t, innerScript, "# trailing comment\n} *> ")
	require.Contains(t, launcher.LogPath, `\sshm-detach-123.log`)
	require.Equal(t, "windows", launcher.Platform)
}

func TestDetectPlatformFromProbeOutput(t *testing.T) {
	require.Equal(t, "windows", detectDetachPlatform("Microsoft Windows [Version 10.0.19045.0]", ""))
	require.Equal(t, "posix", detectDetachPlatform("Linux", ""))
	require.Equal(t, "posix", detectDetachPlatform("", strings.Repeat("x", 10)))
}

func TestParseDetachMetadata(t *testing.T) {
	pid, logPath := parseDetachMetadata("pid=4321\r\nlog=C:\\Users\\ming\\AppData\\Local\\Temp\\sshm.log\r\n")

	require.Equal(t, 4321, pid)
	require.Equal(t, `C:\Users\ming\AppData\Local\Temp\sshm.log`, logPath)
}

func TestBuildDetachedResultUsesConcreteWindowsMetadata(t *testing.T) {
	launcher := buildDetachLauncher("windows", "npm run build", 123)
	result := buildDetachedResult("pc-e5", launcher,
		"pid=4321\r\nlog=C:\\Users\\ming\\AppData\\Local\\Temp\\sshm.log\r\n")

	require.Equal(t, "pc-e5", result["alias"])
	require.Equal(t, "windows", result["platform"])
	require.Equal(t, `C:\Users\ming\AppData\Local\Temp\sshm.log`, result["log_path"])
	require.Equal(t, 4321, result["pid"])
}

func TestBuildDetachedResultRejectsWindowsWithoutLogMetadata(t *testing.T) {
	launcher := buildDetachLauncher("windows", "npm run build", 123)
	result := buildDetachedResult("pc-e5", launcher, "pid=4321\r\n")

	require.Equal(t, map[string]string{
		"kind":    "exec",
		"message": "Windows detach launcher did not return readable log metadata",
	}, result["error"])
}

func TestBuildDetachedResultPreservesPOSIXLogPath(t *testing.T) {
	launcher := buildDetachLauncher("posix", "npm run build", 123)
	result := buildDetachedResult("prod", launcher, "")

	require.Equal(t, "prod", result["alias"])
	require.Equal(t, true, result["detached"])
	require.Equal(t, "posix", result["platform"])
	require.Equal(t, "/tmp/sshm-detach-123.log", result["log_path"])
	require.NotContains(t, result, "pid")
	require.NotContains(t, result, "error")
}
