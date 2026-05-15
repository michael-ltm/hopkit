package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
			if !yes {
				fmt.Fprintf(cmd.OutOrStdout(), "Remove %q? [y/N]: ", alias)
				r := bufio.NewReader(os.Stdin)
				line, _ := r.ReadString('\n')
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
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
			fmt.Fprintf(cmd.OutOrStdout(), "removed %q\n", alias)
			return nil
		},
	}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "do not prompt for confirmation")
	return c
}
