package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	mcppkg "github.com/michael-ltm/sshm/internal/mcp"
	"github.com/spf13/cobra"
)

func newUploadCmd() *cobra.Command {
	var (
		resume  bool
		sha     string
		timeout int
		reason  string
	)
	c := &cobra.Command{
		Use:   "upload <alias> <local_path> <remote_path>",
		Short: "Upload one file over SFTP",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}
			out, err := mcppkg.Upload(ctx, mcpDeps(), map[string]any{
				"alias": args[0], "local_path": args[1], "remote_path": args[2],
				"resume": resume, "sha256": sha, "reason": transferReason(reason, "cli upload"),
			})
			if err != nil {
				return err
			}
			return writeTransferResult(cmd, out)
		},
	}
	c.Flags().BoolVar(&resume, "resume", false, "resume from an existing .part file when possible")
	c.Flags().StringVar(&sha, "sha256", "", "expected SHA-256 checksum")
	c.Flags().IntVarP(&timeout, "timeout", "t", 0, "timeout in seconds (0 = no timeout)")
	c.Flags().StringVar(&reason, "reason", "", "audit reason")
	return c
}

func newDownloadCmd() *cobra.Command {
	var (
		resume  bool
		sha     string
		timeout int
		reason  string
	)
	c := &cobra.Command{
		Use:   "download <alias> <remote_path> <local_path>",
		Short: "Download one file over SFTP",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}
			out, err := mcppkg.Download(ctx, mcpDeps(), map[string]any{
				"alias": args[0], "remote_path": args[1], "local_path": args[2],
				"resume": resume, "sha256": sha, "reason": transferReason(reason, "cli download"),
			})
			if err != nil {
				return err
			}
			return writeTransferResult(cmd, out)
		},
	}
	c.Flags().BoolVar(&resume, "resume", false, "resume from an existing .part file when possible")
	c.Flags().StringVar(&sha, "sha256", "", "expected SHA-256 checksum")
	c.Flags().IntVarP(&timeout, "timeout", "t", 0, "timeout in seconds (0 = no timeout)")
	c.Flags().StringVar(&reason, "reason", "", "audit reason")
	return c
}

func mcpDeps() mcppkg.Deps {
	return mcppkg.Deps{ConfigPath: configPath(), AuditPath: config.AuditPath(), AllowWrite: true}
}

func transferReason(custom, fallback string) string {
	if custom != "" {
		return custom
	}
	return fallback
}

func writeTransferResult(cmd *cobra.Command, out any) error {
	if flagJSON {
		return writeJSON(cmd.OutOrStdout(), out)
	}
	m, ok := out.(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected transfer result")
	}
	if e, ok := m["error"]; ok {
		return fmt.Errorf("%v", e)
	}
	if local, ok := m["local_path"].(string); ok {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "downloaded %v bytes to %s\n", m["bytes"], local)
		return err
	}
	if remote, ok := m["remote_path"].(string); ok {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "uploaded %v bytes to %s\n", m["bytes"], remote)
		return err
	}
	return writeJSON(cmd.OutOrStdout(), out)
}
