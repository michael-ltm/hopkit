package commands

import (
	"context"
	"fmt"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
	"sort"
	"sync"
	"time"
)

func newInspectCmd() *cobra.Command {
	var all, local bool
	var timeout int
	c := &cobra.Command{Use: "inspect [alias]", Short: "Inspect system and hardware without changing last-use time", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if local {
			if all || len(args) > 0 {
				return fmt.Errorf("--local cannot be combined with a remote target")
			}
			return writeJSON(cmd.OutOrStdout(), inventory.Collect(cmd.Context()))
		}
		if timeout < 1 || timeout > 60 {
			return fmt.Errorf("timeout must be 1–60 seconds")
		}
		cfg, _, e := loadConfig()
		if e != nil {
			return e
		}
		var aliases []string
		if all {
			for a := range cfg.Servers {
				aliases = append(aliases, a)
			}
		} else if len(args) == 1 {
			if _, e = resolveServer(cfg, args[0]); e != nil {
				return e
			}
			aliases = []string{args[0]}
		} else {
			return fmt.Errorf("choose an alias or --all")
		}
		sort.Strings(aliases)
		type row struct {
			Alias       string              `json:"alias"`
			Platform    string              `json:"platform,omitempty"`
			Status      string              `json:"status"`
			SSHMStatus  string              `json:"sshm_status"`
			SSHMVersion string              `json:"sshm_version,omitempty"`
			Hardware    *inventory.Snapshot `json:"hardware,omitempty"`
		}
		rows := make([]row, len(aliases))
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for i, a := range aliases {
			wg.Add(1)
			go func(i int, a string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-cmd.Context().Done():
					return
				}
				defer func() { <-sem }()
				s := cfg.Servers[a]
				r := row{Alias: a, Platform: s.Platform, SSHMStatus: "unknown"}
				defer func() { rows[i] = r }()
				if s.Auth == config.AuthPassword {
					r.Status = "password required; not prompted"
					return
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeout)*time.Second)
				defer cancel()
				client, e := sshpkg.Dial(s, sshpkg.BuildOpts{ProbeOnly: true, ConfigPath: configPath(), Timeout: time.Duration(timeout) * time.Second})
				if e != nil {
					r.Status = sshpkg.FailureCategory(e)
					r.Hardware = inventory.Parse(s.Platform, "", e)
					_ = sshpkg.RecordHardware(configPath(), a, s, r.Hardware)
					_ = sshpkg.RecordSSHM(configPath(), a, s, "unknown", s.SSHMVersion, time.Now())
					_ = config.RecordSSHCheck(configPath(), a, s, r.Status, time.Now())
					return
				}
				defer client.Close()
				_ = config.RecordSSHCheck(configPath(), a, s, "", time.Now())
				r.Platform = client.DetectPlatform(ctx)
				r.SSHMStatus, r.SSHMVersion = client.DetectSSHM(ctx, r.Platform)
				r.Hardware = client.DetectHardware(ctx, r.Platform)
				if err := sshpkg.RecordHardware(configPath(), a, s, r.Hardware); err != nil {
					r.Status = "not saved"
				}
				_ = sshpkg.RecordSSHM(configPath(), a, s, r.SSHMStatus, r.SSHMVersion, time.Now())
				if r.Platform == "" {
					r.Status = "unknown"
				} else {
					r.Status = "detected"
					if e = sshpkg.RecordPlatform(configPath(), a, s, r.Platform); e != nil {
						r.Status = "not saved"
					}
				}
				_ = config.RecordProbes(configPath(), map[string]config.ProbeObservation{a: config.NewProbeObservation(s, true, time.Now())})
			}(i, a)
		}
		wg.Wait()
		if e := cmd.Context().Err(); e != nil {
			return e
		}
		return writeJSON(cmd.OutOrStdout(), rows)
	}}
	c.Flags().BoolVar(&all, "all", false, "inspect all configured targets with at most four connections at once")
	c.Flags().BoolVar(&local, "local", false, "inspect this device without SSH or cloud login")
	c.Flags().IntVar(&timeout, "timeout", 15, "per-target timeout in seconds")
	return c
}
