package commands

import (
	"fmt"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/spf13/cobra"
)

func newLsCmd() *cobra.Command {
	var interactive bool
	var plain bool
	command := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "Browse and manage configured servers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), struct {
					Default string                    `json:"default,omitempty"`
					Servers map[string]*config.Server `json:"servers"`
				}{Default: cfg.Default, Servers: cfg.Servers})
			}
			if interactive || (!plain && commandHasTerminal(cmd)) {
				return runServerManager(cmd)
			}
			icons := ui.ResolveIcons(cfg.UI.Icons)
			color := !flagNoColor
			if _, err := fmt.Fprint(cmd.OutOrStdout(), ui.RenderServerTable(cfg.Servers, icons, color)); err != nil {
				return err
			}
			return nil
		},
	}
	command.Flags().BoolVarP(&interactive, "interactive", "i", false, "open the interactive server manager even when auto-detection is unavailable")
	command.Flags().BoolVar(&plain, "plain", false, "print the table instead of opening the interactive manager")
	command.MarkFlagsMutuallyExclusive("interactive", "plain")
	return command
}
