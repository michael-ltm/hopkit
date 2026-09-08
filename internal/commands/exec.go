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
	"golang.org/x/term"
)

func newExecCmd() *cobra.Command {
	var timeoutSec int
	var insecure bool
	var askPassword bool
	var rawEnvironment bool
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
			if s.CloudEntry != "" {
				if rawEnvironment {
					return fmt.Errorf("--raw-environment is only supported for direct SSH connections")
				}
				return runCloudReference(cmd, s, append([]string{s.CloudEntry}, args[1:]...), true, timeoutSec)
			}
			remoteCmd := strings.Join(args[1:], " ")
			ctx := context.Background()
			if timeoutSec > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
				defer cancel()
			}
			var password []byte
			if s.Auth == config.AuthPassword {
				if !askPassword {
					return fmt.Errorf("auth=password requires --ask-password")
				}
				if !term.IsTerminal(int(os.Stdin.Fd())) {
					return fmt.Errorf("--ask-password requires an interactive terminal; use key or agent auth for automation")
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Password for %s@%s: ", s.User, s.Host)
				password, err = term.ReadPassword(int(os.Stdin.Fd()))
				_, _ = fmt.Fprintln(cmd.ErrOrStderr())
				if err != nil {
					return err
				}
			}
			defer func() {
				for i := range password {
					password[i] = 0
				}
			}()
			return execOnce(ctx, cmd, args[0], s, remoteCmd, insecure, string(password), rawEnvironment)
		},
	}
	c.Flags().IntVarP(&timeoutSec, "timeout", "t", 0, "timeout in seconds (0 = no timeout)")
	c.Flags().BoolVar(&insecure, "insecure", false, "disable host-key verification (skip known_hosts check)")
	c.Flags().BoolVar(&rawEnvironment, "raw-environment", false, "retain exact sshd environment without login profiles or PATH additions")
	c.Flags().BoolVar(&askPassword, "ask-password", false, "prompt for the password when the alias uses auth=password")
	return c
}

func execOnce(ctx context.Context, cmd *cobra.Command, alias string, s *config.Server, remoteCmd string, insecure bool, password string, rawEnvironment bool) error {
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{Password: password, Insecure: insecure, Alias: alias, ConfigPath: configPath()})
	if err != nil {
		return err
	}
	defer cli.Close()
	if !rawEnvironment {
		remoteCmd, err = cli.PrepareUserCommand(ctx, remoteCmd)
		if err != nil {
			return err
		}
	}
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
