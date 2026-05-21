package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/bootstrap"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var timeoutSec int
	c := &cobra.Command{
		Use:   "init <alias>",
		Short: "Run baseline hardening (install fail2ban etc.) on a server",
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
			ctx := context.Background()
			if timeoutSec > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
				defer cancel()
			}
			res, err := bootstrap.Run(ctx, s)
			if err != nil {
				return err
			}
			// Persist the init_state so `ls`/`show` reflect it.
			if res.Completed {
				s.InitState = config.InitBootstrapped
				if err := saveConfig(cfg); err != nil {
					return err
				}
			}
			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{args[0]: res})
			}
			return renderInitResult(cmd, args[0], res)
		},
	}
	c.Flags().IntVarP(&timeoutSec, "timeout", "t", 120, "timeout in seconds (0 = no timeout)")
	return c
}

func renderInitResult(cmd *cobra.Command, alias string, r bootstrap.Result) error {
	status := "incomplete"
	if r.Completed {
		status = "done"
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "bootstrap %s: %s\n", alias, status); err != nil {
		return err
	}
	if len(r.SSHDState) > 0 {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "sshd auth state:\n  %s\n", strings.Join(r.SSHDState, "\n  ")); err != nil {
			return err
		}
	}
	return nil
}
