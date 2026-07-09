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
