package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func newExecCmd() *cobra.Command {
	var timeoutSec int
	c := &cobra.Command{
		Use:   "exec <alias> <command...>",
		Short: "Run a command on a server",
		Long: `Run a single command on the remote server.

The command and its arguments are joined with spaces and run through the
remote shell. For commands containing quoted strings, escape your local
shell or wrap in 'sh -c "..."', e.g.:

    sshm exec myhost sh -c 'grep -r "hello world" /tmp'
`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("requires alias")
			}
			if len(args) < 2 {
				return fmt.Errorf("requires a command to run after the alias")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			s, err := resolveServer(cfg, args[0])
			if err != nil {
				return err
			}
			remoteCmd := strings.Join(args[1:], " ")
			ctx := context.Background()
			if timeoutSec > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
				defer cancel()
			}
			return execOnce(ctx, cmd, s, remoteCmd)
		},
	}
	c.Flags().IntVarP(&timeoutSec, "timeout", "t", 0, "timeout in seconds (0 = no timeout)")
	return c
}

func execOnce(ctx context.Context, cmd *cobra.Command, s *config.Server, remoteCmd string) error {
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return err
	}
	defer cli.Close()
	if flagJSON {
		res, err := cli.Exec(ctx, remoteCmd)
		if err != nil {
			return err
		}
		return writeJSON(cmd.OutOrStdout(), res)
	}
	exit, err := cli.StreamExec(ctx, remoteCmd, cmd.OutOrStdout(), cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	if exit != 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "exit code: %d\n", exit)
		os.Exit(exit)
	}
	return nil
}
