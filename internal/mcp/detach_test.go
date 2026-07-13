package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildDetachLauncherUsesPowerShellForWindows(t *testing.T) {
	launcher := buildDetachLauncher("windows", "npm run build", 123)

	require.Contains(t, launcher.Command, "Start-Process")
	require.Contains(t, launcher.Command, "powershell.exe")
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
