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
	var cloud bool
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
			if err := config.CheckServerRemoval(cfg, alias); err != nil {
				return err
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
			srv := cfg.Servers[alias]
			cloudToo := cloud
			if !cloudToo && !yes && srv != nil && srv.CloudEntry != "" && commandHasTerminal(cmd) {
				cloudToo, err = confirmCloudRemoval(cmd)
				if err != nil {
					return err
				}
			}
			if err := removeServer(alias); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "removed %q\n", alias); err != nil {
				return err
			}
			if cloudToo && srv != nil {
				if err := removeCloudEntry(cmd, alias, srv.CloudEntry); err != nil {
					return fmt.Errorf("local removal succeeded, but the cloud tombstone failed: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Cloud entry marked for deletion; run `sshm cloud sync` to push it.")
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "do not prompt for confirmation")
	c.Flags().BoolVar(&cloud, "cloud", false, "also tombstone the cloud vault entry (run sshm cloud sync to push)")
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
