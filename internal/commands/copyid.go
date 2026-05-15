package commands

import (
	"context"
	"fmt"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newCopyIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "copy-id <alias>",
		Short: "Install the local public key on the remote (one-shot password)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			s, err := resolveServer(cfg, args[0])
			if err != nil {
				return err
			}
			if s.Auth != config.AuthKey || s.KeyPath == "" {
				return fmt.Errorf("alias %q must have auth=key and a key_path set", args[0])
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Password for %s@%s: ", s.User, s.Host)
			pw, err := term.ReadPassword(0)
			fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			ctx := context.Background()
			if err := keys.CopyID(ctx, s, string(pw), s.KeyPath); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "public key installed"); err != nil {
				return err
			}
			return nil
		},
	}
}
