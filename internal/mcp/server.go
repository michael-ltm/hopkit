package mcp

import (
	"context"
	"errors"

	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

// Deps is the non-global state an MCP server needs: where the config and
// audit log live. Passing these explicitly keeps the server testable.
type Deps struct {
	ConfigPath      string
	AuditPath       string
	AllowWrite      bool   // when false, write/exec tools are not registered
	Version         string // build version (set by ldflags via commands.Version); falls back to "dev"
	TransferManager *transferManager
	CloudSession    *CloudSession
}

// NewServer builds the MCP server with every sshm tool registered, and
// returns the registered tool names for verification.
func NewServer(deps Deps) (*server.MCPServer, []string) {
	ver := deps.Version
	if ver == "" {
		ver = "dev"
	}
	if deps.TransferManager == nil {
		deps.TransferManager = defaultTransferManager
	}
	s := server.NewMCPServer("sshm", ver)
	var names []string
	names = registerReadTools(s, deps, names)
	names = registerProjectReadTools(s, deps, names)
	if deps.AllowWrite {
		if deps.CloudSession != nil {
			names = registerCloudTools(s, deps, names)
		}
		names = registerWriteTools(s, deps, names)
		names = registerProjectWriteTools(s, deps, names)
		names = registerExecTools(s, deps, names)
		names = registerEnvironmentTool(s, deps, names)
		names = registerProjectExecTool(s, deps, names)
		names = registerOpsTools(s, deps, names)
		names = registerTransferTools(s, deps, names)
	}
	return s, names
}

// sshOptions uses local authentication unless a browser session was explicitly supplied.
func (deps Deps) sshOptions(ctx context.Context, opts sshpkg.BuildOpts) sshpkg.BuildOpts {
	if deps.CloudSession != nil {
		// A cloud-bound jump may require approval even when the final target
		// has native auth. Never bypass a denied jump with direct fallback.
		opts.StrictRoute = true
		opts.ResolveCloud = func(target *config.Server, options sshpkg.BuildOpts) (*config.Server, sshpkg.BuildOpts, func(), error) {
			if !deps.AllowWrite {
				return nil, options, nil, errors.New("browser credential access is unavailable in read-only MCP mode")
			}
			return deps.CloudSession.Resolve(ctx, target, options)
		}
	}
	return opts
}
