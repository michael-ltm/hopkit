package commands

import (
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "connect <alias>",
		Aliases: []string{"c"},
		Short:   "Open an interactive SSH session",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			alias := ""
			if len(args) == 1 {
				alias = args[0]
			}
			s, err := resolveServer(cfg, alias)
			if err != nil {
				return err
			}
			return connect(s)
		},
	}
}

func connect(s *config.Server) error {
	c, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return err
	}
	defer c.Close()
	return c.AttachInteractive()
}
