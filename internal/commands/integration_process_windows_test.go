//go:build windows

package commands

import (
	"context"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsNPMShimPreservesArguments(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "folder with spaces")
	require.NoError(t, os.Mkdir(dir, 0700))
	shim := filepath.Join(dir, "codex.cmd")
	require.NoError(t, os.WriteFile(shim, []byte("@echo off\r\nif \"%~1\"==\"mcp\" if \"%~2\"==\"get\" if \"%~3\"==\"sshm\" exit /b 0\r\nexit /b 7\r\n"), 0600))
	cmd, err := integrationProcess(context.Background(), shim, "mcp", "get", "sshm")
	require.NoError(t, err)
	require.NoError(t, cmd.Run())
	_, err = integrationProcess(context.Background(), filepath.Join(dir, "bad&name.cmd"), "mcp")
	require.Error(t, err)
}
