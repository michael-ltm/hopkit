package mcp

import (
	"github.com/mark3labs/mcp-go/server"
)

// Deps is the non-global state an MCP server needs: where the config and
// audit log live. Passing these explicitly keeps the server testable.
type Deps struct {
	ConfigPath string
	AuditPath  string
	AllowWrite bool // when false, write/exec tools are not registered
}

// NewServer builds the MCP server with every sshm tool registered, and
// returns the registered tool names for verification.
func NewServer(deps Deps) (*server.MCPServer, []string) {
	s := server.NewMCPServer("sshm", "0.2.0")
	var names []string
	names = registerReadTools(s, deps, names)
	if deps.AllowWrite {
		names = registerWriteTools(s, deps, names)
		names = registerExecTools(s, deps, names)
		names = registerOpsTools(s, deps, names)
	}
	return s, names
}
