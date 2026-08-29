package commands

import (
	"context"
	"fmt"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
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
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer func() {
				for i := range pw {
					pw[i] = 0
				}
			}()
			// TODO(v0.3): expose a --timeout flag instead of unbounded context.
			ctx := context.Background()
			if err := keys.CopyID(ctx, s, string(pw), s.KeyPath, sshpkg.BuildOpts{Alias: args[0], ConfigPath: configPath()}); err != nil {
				return err
			}
			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]string{
					"alias":  args[0],
					"result": "installed",
				})
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "public key installed"); err != nil {
				return err
			}
			return nil
		},
	}
}
