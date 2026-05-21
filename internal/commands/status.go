package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/michael-ltm/sshm/internal/status"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	var timeoutSec int
	c := &cobra.Command{
		Use:   "status <alias>",
		Short: "Show a resource snapshot for a server",
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
			snap, err := status.Collect(ctx, s)
			if err != nil {
				return err
			}
			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{args[0]: snap})
			}
			return renderSnapshot(cmd, args[0], snap)
		},
	}
	c.Flags().IntVarP(&timeoutSec, "timeout", "t", 15, "timeout in seconds")
	return c
}

func renderSnapshot(cmd *cobra.Command, alias string, s status.Snapshot) error {
	rows := [][2]string{
		{"Server", alias},
		{"Uptime", s.Uptime},
		{"Load", s.Load},
		{"Memory", s.Memory},
		{"Disk", s.Disk},
		{"Open ports", fmt.Sprintf("%v", s.OpenPorts)},
		{"Failed logins", fmt.Sprintf("%d", s.FailedLogins)},
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%-15s %s\n", r[0], r[1]); err != nil {
			return err
		}
	}
	return nil
}
