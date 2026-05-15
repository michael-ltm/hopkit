package commands

import (
	"fmt"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/spf13/cobra"
)

func newLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List configured servers",
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
			icons := ui.ResolveIcons(cfg.UI.Icons)
			color := !flagNoColor
			if _, err := fmt.Fprint(cmd.OutOrStdout(), ui.RenderServerTable(cfg.Servers, icons, color)); err != nil {
				return err
			}
			return nil
		},
	}
}
