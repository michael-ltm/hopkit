package commands

import (
	"fmt"
	"path/filepath"

	"github.com/michael-ltm/sshm/internal/keys"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func newGenKeyCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "gen-key <alias>",
		Short: "Generate an ed25519 keypair for an alias and update its key_path",
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
			actualPath := path
			if actualPath == "" {
				actualPath = filepath.Join("~", ".ssh", "id_ed25519_"+args[0])
			}
			expanded, err := sshpkg.ExpandHome(actualPath)
			if err != nil {
				return err
			}
			pub, err := keys.GenerateED25519(expanded, args[0]+"@sshm")
			if err != nil {
				return err
			}
			s.KeyPath = actualPath
			if err := saveConfig(cfg); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), expanded); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), pub); err != nil {
				return err
			}
			return nil
		},
	}
	c.Flags().StringVarP(&path, "path", "p", "", "key path (default ~/.ssh/id_ed25519_<alias>)")
	return c
}
