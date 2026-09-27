package commands

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/michael-ltm/sshm/internal/status"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/spf13/cobra"
)

func newTestCmd() *cobra.Command {
	var (
		all     bool
		timeout int
	)
	c := &cobra.Command{
		Use:   "test [<alias>]",
		Short: "Test reachability through the configured SSH route",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			to := time.Duration(timeout) * time.Second
			ctx := context.Background()
			icons := ui.ResolveIcons(cfg.UI.Icons)
			if all || len(args) == 0 {
				res := status.ProbeManyWithOptions(ctx, cfg.Servers, to, sshpkg.BuildOpts{ConfigPath: configPath()})
				probes := make(map[string]config.ProbeObservation, len(res))
				for alias, result := range res {
					probes[alias] = config.NewProbeObservation(cfg.Servers[alias], result.Reachable, result.ObservedAt)
				}
				if err := config.RecordProbes(configPath(), probes); err != nil {
					return err
				}
				if flagJSON {
					return writeJSON(cmd.OutOrStdout(), res)
				}
				aliases := make([]string, 0, len(res))
				for a := range res {
					aliases = append(aliases, a)
				}
				sort.Strings(aliases)
				for _, alias := range aliases {
					if err := printProbe(cmd, alias, res[alias], icons); err != nil {
						return err
					}
				}
				return nil
			}
			s, err := resolveServer(cfg, args[0])
			if err != nil {
				return err
			}
			r := status.ProbeWithOptions(ctx, s, to, sshpkg.BuildOpts{ConfigPath: configPath()})
			if err := config.RecordProbes(configPath(), map[string]config.ProbeObservation{
				args[0]: config.NewProbeObservation(s, r.Reachable, r.ObservedAt),
			}); err != nil {
				return err
			}
			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]status.Result{args[0]: r})
			}
			return printProbe(cmd, args[0], r, icons)
		},
	}
	c.Flags().BoolVar(&all, "all", false, "test every configured server through their configured SSH routes")
	c.Flags().IntVarP(&timeout, "timeout", "t", 3, "per-server route probe timeout (seconds)")
	return c
}

func printProbe(cmd *cobra.Command, alias string, r status.Result, ic ui.IconSet) error {
	icon := ic.Online
	if !r.Reachable {
		icon = ic.Offline
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %-20s offline via %s — %s\n", icon, alias, r.Route, r.Error); err != nil {
			return err
		}
		return nil
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %-20s online via %s (%s)\n", icon, alias, r.Route, r.Latency); err != nil {
		return err
	}
	return nil
}
