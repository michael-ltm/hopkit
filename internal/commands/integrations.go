package commands

import (
	"context"
	"fmt"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/integrations"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func integrationApps(app string) ([]string, error) {
	if app == "all" {
		return []string{"codex", "claude"}, nil
	}
	if app == "codex" || app == "claude" {
		return []string{app}, nil
	}
	return nil, fmt.Errorf("choose --app codex, claude or all")
}
func newIntegrationsCmd() *cobra.Command {
	root := &cobra.Command{Use: "integrations", Short: "Install and safely refresh Codex / Claude Code skills and optional MCP setup"}
	var app string
	root.PersistentFlags().StringVar(&app, "app", "all", "codex, claude or all")
	root.AddCommand(&cobra.Command{Use: "status", Short: "Inspect managed skills without revealing app configuration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		apps, e := integrationApps(app)
		if e != nil {
			return e
		}
		var statuses []integrations.Status
		for _, a := range apps {
			s, e := integrations.Inspect(home, a)
			if e != nil {
				return e
			}
			statuses = append(statuses, s)
		}
		return writeJSON(cmd.OutOrStdout(), statuses)
	}})
	for _, operation := range []string{"install", "refresh"} {
		op := operation
		var mcp bool
		c := &cobra.Command{Use: op, Short: op + " SSHM-managed skill documents; preserve edited and plugin-managed files", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			// Legacy updaters launch the new binary via integrations refresh.
			// Report its installation even when the parent remains an old agent.
			if op == "refresh" {
				_ = reportClientVersion(cmd.Context())
			}
			home, e := os.UserHomeDir()
			if e != nil {
				return e
			}
			apps, e := integrationApps(app)
			if e != nil {
				return e
			}
			var failed bool
			for _, a := range apps {
				message, e := integrations.Install(home, a, Version, op == "refresh")
				if e != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: %v\n", a, e)
					failed = true
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", a, message)
				if mcp {
					s, _ := integrations.Inspect(home, a)
					if s.Plugin {
						fmt.Fprintln(cmd.OutOrStdout(), a+": existing plugin MCP retained")
						continue
					}
					if e = registerMCP(cmd, home, a); e != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "%s MCP: %v\n", a, e)
						failed = true
					}
				}
			}
			if failed {
				return fmt.Errorf("some integrations were retained; see messages above")
			}
			return nil
		}}
		if op == "install" {
			c.Flags().BoolVar(&mcp, "mcp", false, "also register a missing sshm MCP server through the selected app's CLI")
		}
		root.AddCommand(c)
	}
	return root
}
func registerMCP(cmd *cobra.Command, home, app string) error {
	binary, e := exec.LookPath(app)
	if e != nil {
		return fmt.Errorf("%s CLI not found; skill installed, MCP setup deferred", app)
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()
	get, e := integrationProcess(ctx, binary, "mcp", "get", "sshm")
	if e != nil {
		return e
	}
	output, e := get.CombinedOutput()
	if e == nil {
		fmt.Fprintln(cmd.OutOrStdout(), app+": existing sshm MCP configuration retained")
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("cannot inspect existing MCP configuration")
	}
	lower := strings.ToLower(string(output))
	if !strings.Contains(lower, "not found") && !strings.Contains(lower, "no mcp server") && !strings.Contains(lower, "no server") {
		return fmt.Errorf("MCP configuration could not be verified; no changes made")
	}
	path := filepath.Join(home, ".claude.json")
	if app == "codex" {
		base := os.Getenv("CODEX_HOME")
		if base == "" {
			base = filepath.Join(home, ".codex")
		}
		path = filepath.Join(base, "config.toml")
	}
	if b, e := os.ReadFile(path); e == nil {
		defer cloudsync.Wipe(b)
		if e = cloudsync.WritePrivate(fmt.Sprintf("%s.sshm-backup-%d", path, time.Now().UnixNano()), b); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	self, e = filepath.EvalSymlinks(self)
	if e != nil {
		return e
	}
	args := []string{"mcp", "add", "sshm", "--", self, "mcp"}
	if app == "claude" {
		args = []string{"mcp", "add", "--scope", "user", "sshm", "--", self, "mcp"}
	}
	install, e := integrationProcess(ctx, binary, args...)
	if e != nil {
		return e
	}
	if _, e = install.CombinedOutput(); e != nil {
		return fmt.Errorf("app CLI could not register MCP; private configuration backup was retained")
	}
	verify, e := integrationProcess(ctx, binary, "mcp", "get", "sshm")
	if e != nil {
		return e
	}
	if _, e = verify.CombinedOutput(); e != nil {
		return fmt.Errorf("MCP registration readback failed")
	}
	fmt.Fprintln(cmd.OutOrStdout(), app+": sshm MCP registered; restart the app to load it")
	return nil
}
