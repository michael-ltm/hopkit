package commands

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	mcppkg "github.com/michael-ltm/sshm/internal/mcp"
	"github.com/spf13/cobra"
)

func newMcpCmd() *cobra.Command {
	var readOnly bool
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Start the MCP server (stdio) for AI assistants",
		Long: `Start sshm's Model Context Protocol server on stdio.

AI hosts (Claude Code, Cursor, Codex, Gemini CLI) spawn this as a
subprocess. stdout carries the MCP protocol; do not pipe it. Logs go
to stderr; mutations are recorded to the audit log.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			deps := mcppkg.Deps{
				ConfigPath: configPath(),
				AuditPath:  config.AuditPath(),
				AllowWrite: !readOnly,
				Version:    Version,
			}
			s, _ := mcppkg.NewServer(deps)
			return server.ServeStdio(s)
		},
	}
	c.Flags().BoolVar(&readOnly, "read-only", false, "register only read tools (no add/edit/exec/bootstrap)")
	return c
}
