package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/spf13/cobra"
)

func reportClientVersion(ctx context.Context) error {
	// Read-only access: agents may hold the vault lock for long-lived sessions.
	s, err := cloudsync.LoadState(cloudsync.StatePath(configPath()))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.ReportInstalledVersion(ctx)
}
func newCloudReportVersionCmd() *cobra.Command {
	var quiet bool
	c := &cobra.Command{Use: "report-version", Short: "Refresh this client's installed version without unlocking the vault", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		err := reportClientVersion(cmd.Context())
		if quiet {
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Installed client version reported. Running agents retain their version until restarted.")
		return nil
	}}
	c.Flags().BoolVar(&quiet, "quiet", false, "best effort; skip errors for offline or local-only installations")
	return c
}
