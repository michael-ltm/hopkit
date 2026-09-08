package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/michael-ltm/sshm/internal/desktopsession"
	"github.com/spf13/cobra"
)

func newDesktopCmd() *cobra.Command {
	c := &cobra.Command{Use: "desktop", Short: "Manage opt-in macOS desktop-session execution for existing keychain logins", Args: cobra.NoArgs}
	c.AddCommand(&cobra.Command{Use: "enable", Short: "Enable same-user desktop execution (requires an existing macOS desktop login)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
		defer cancel()
		path, e := os.Executable()
		if e != nil {
			return e
		}
		s, e := desktopsession.Enable(ctx, path)
		if e != nil {
			return e
		}
		return writeJSON(cmd.OutOrStdout(), s)
	}})
	c.AddCommand(&cobra.Command{Use: "status", Short: "Inspect desktop execution without reading credentials", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return writeJSON(cmd.OutOrStdout(), desktopsession.Inspect(cmd.Context()))
	}})
	c.AddCommand(&cobra.Command{Use: "disable", Short: "Disable desktop execution and stop its active commands", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return desktopsession.Disable(cmd.Context())
	}})
	c.AddCommand(&cobra.Command{Use: "serve", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return desktopsession.Serve(ctx, Version)
	}})
	c.AddCommand(&cobra.Command{Use: "exec -- <command>", Short: "Execute once through this user's private desktop socket", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		dir, e := os.Getwd()
		if e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer cancel()
		code, e := desktopsession.Execute(ctx, args[0], dir, cmd.OutOrStdout(), cmd.ErrOrStderr())
		if e != nil {
			return e
		}
		if code != 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "exit code: %d\n", code)
			os.Exit(code)
		}
		return nil
	}})
	return c
}
