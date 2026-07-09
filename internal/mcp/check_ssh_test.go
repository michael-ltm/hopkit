package mcp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckSSHModeDefaultsToExec(t *testing.T) {
	require.Equal(t, sshCheckExec, sshCheckMode(map[string]any{}))
	require.Equal(t, sshCheckTCP, sshCheckMode(map[string]any{"mode": "tcp"}))
	require.Equal(t, sshCheckHandshake, sshCheckMode(map[string]any{"mode": "handshake"}))
	require.Equal(t, sshCheckAuth, sshCheckMode(map[string]any{"mode": "auth"}))
	require.Equal(t, sshCheckExec, sshCheckMode(map[string]any{"mode": "nonsense"}))
}
