package commands

import (
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	mcppkg "github.com/michael-ltm/sshm/internal/mcp"
	"github.com/spf13/cobra"
)

func newMcpCmd() *cobra.Command {
	return newMcpCmdWithRunner(func(readOnly bool, cloudAuth string, policy mcppkg.CloudSessionPolicy) error {
		var session *mcppkg.CloudSession
		if cloudAuth == "browser" {
			var err error
			session, err = mcppkg.NewCloudSessionWithPolicy(configPath(), policy)
			if err != nil {
				return err
			}
			defer session.Close()
		}
		deps := mcppkg.Deps{
			CloudSession: session,
			ConfigPath:   configPath(),
			AuditPath:    config.AuditPath(),
			AllowWrite:   !readOnly,
			Version:      Version,
		}
		s, _ := mcppkg.NewServer(deps)
		return server.ServeStdio(s)
	})
}

func newMcpCmdWithRunner(run func(bool, string, mcppkg.CloudSessionPolicy) error) *cobra.Command {
	var readOnly bool
	var cloudAuth string
	defaults := mcppkg.DefaultCloudSessionPolicy()
	var idleTimeout time.Duration
	var maximumAge time.Duration
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Start the MCP server (stdio) for AI assistants",
		Long: `Start sshm's Model Context Protocol server on stdio.

AI hosts (Claude Code, Cursor, Codex, Gemini CLI) spawn this as a
subprocess. stdout carries the MCP protocol; do not pipe it. Logs go
to stderr; mutations are recorded to the audit log.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if cloudAuth != "local" && cloudAuth != "browser" {
				return fmt.Errorf("--cloud-auth must be local or browser")
			}
			if readOnly && cloudAuth == "browser" {
				return fmt.Errorf("--cloud-auth browser cannot be combined with --read-only")
			}
			policy := mcppkg.CloudSessionPolicy{IdleTimeout: idleTimeout, MaximumAge: maximumAge}
			if err := policy.Validate(); err != nil {
				return err
			}
			return run(readOnly, cloudAuth, policy)
		},
	}
	c.Flags().BoolVar(&readOnly, "read-only", false, "register only read tools (no add/edit/exec/bootstrap)")
	c.Flags().StringVar(&cloudAuth, "cloud-auth", "local", "SSH credential access: local keys/agent or browser-approved cloud session")
	c.Flags().DurationVar(&idleTimeout, "cloud-idle-timeout", defaults.IdleTimeout, "lock cloud credentials after this much inactivity (maximum 720h / 30 days)")
	c.Flags().DurationVar(&maximumAge, "cloud-session-max-age", defaults.MaximumAge, "lock cloud credentials after this total session age (maximum 720h / 30 days)")
	return c
}
