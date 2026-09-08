package commands

import (
	"context"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
	"time"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{Use: "doctor [alias]", Short: "Check CLI discovery and GitHub access in this session (no credentials printed)", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if len(args) == 0 {
			r, err := sshpkg.CheckLocalEnvironment(ctx)
			if err != nil {
				return err
			}
			return writeJSON(cmd.OutOrStdout(), r)
		}
		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}
		s, err := resolveServer(cfg, args[0])
		if err != nil {
			return err
		}
		c, err := sshpkg.Dial(s, sshpkg.BuildOpts{ConfigPath: configPath(), Alias: args[0], ProbeOnly: true})
		if err != nil {
			return err
		}
		defer c.Close()
		r, err := c.CheckEnvironment(ctx)
		if err != nil {
			return err
		}
		return writeJSON(cmd.OutOrStdout(), r)
	}}
}
