package commands

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/spf13/cobra"
)

func newRmCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "rm <alias>",
		Short: "Remove a configured server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			alias := args[0]
			if _, ok := cfg.Servers[alias]; !ok {
				return fmt.Errorf("unknown server %q", alias)
			}
			if projects := config.ProjectsUsingServer(cfg, alias); len(projects) > 0 {
				return fmt.Errorf("server %q is used by project profiles: %s; update those profiles first", alias, strings.Join(projects, ", "))
			}
			if !yes {
				confirmed, err := confirmExactAlias(cmd, alias, "remove this server")
				if err != nil {
					return err
				}
				if !confirmed {
					fmt.Fprintln(cmd.OutOrStdout(), "aborted")
					return nil
				}
			}
			delete(cfg.Servers, alias)
			if cfg.Default == alias {
				cfg.Default = ""
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "removed %q\n", alias); err != nil {
				return err
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "do not prompt for confirmation")
	return c
}

func confirmExactAlias(cmd *cobra.Command, alias, action string) (bool, error) {
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "To %s, type %q exactly: ", action, alias); err != nil {
		return false, err
	}
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return false, err
	}
	return strings.TrimSpace(line) == alias, nil
}
