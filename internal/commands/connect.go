package commands

import (
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	var insecure bool
	c := &cobra.Command{
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
			return connect(s, insecure)
		},
	}
	c.Flags().BoolVar(&insecure, "insecure", false, "disable host-key verification (skip known_hosts check)")
	return c
}

func connect(s *config.Server, insecure bool) error {
	c, err := sshpkg.Dial(s, sshpkg.BuildOpts{Insecure: insecure})
	if err != nil {
		return err
	}
	defer c.Close()
	return c.AttachInteractive()
}
