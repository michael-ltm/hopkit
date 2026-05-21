package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewMcpCmd_HasCorrectMetadata(t *testing.T) {
	cmd := newMcpCmd()
	require.Equal(t, "mcp", cmd.Name())
	require.Contains(t, cmd.Short, "MCP")
}
