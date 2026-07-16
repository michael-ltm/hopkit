package commands

import (
	"fmt"
	"os"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
			return connect(s, insecure, configPath())
		},
	}
	c.Flags().BoolVar(&insecure, "insecure", false, "disable host-key verification (skip known_hosts check)")
	return c
}

func connect(s *config.Server, insecure bool, activeConfigPath string) error {
	c, err := dialInteractive(s, insecure, activeConfigPath)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.AttachInteractive()
}

func dialInteractive(s *config.Server, insecure bool, activeConfigPath string) (*sshpkg.Client, error) {
	opts := sshpkg.BuildOpts{Insecure: insecure, ConfigPath: activeConfigPath}
	var password []byte
	if s.Auth == config.AuthPassword {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("auth=password requires an interactive terminal; use key or agent auth for automation")
		}
		fmt.Fprintf(os.Stderr, "Current password for %s@%s: ", s.User, s.Host)
		var err error
		password, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		opts.Password = string(password)
	}
	defer func() {
		for index := range password {
			password[index] = 0
		}
	}()
	return sshpkg.Dial(s, opts)
}
