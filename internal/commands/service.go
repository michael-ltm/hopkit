package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/michael-ltm/sshm/internal/localservice"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/spf13/cobra"
)

func newServiceCmd() *cobra.Command {
	service := &cobra.Command{Use: "service", Short: "Manage the local credential service"}
	terminal := func(cmd *cobra.Command) error {
		if !commandHasTerminal(cmd) {
			return errors.New("this operation requires a local interactive terminal")
		}
		return nil
	}
	setup := &cobra.Command{Use: "setup", Short: "Protect local credentials and start the service", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if e := terminal(cmd); e != nil {
			return e
		}
		s := localstore.New(configPath())
		if e := s.Ensure(cmd.Context()); e != nil {
			return e
		}
		if e := setupLocalCredentials(cmd); e != nil {
			return e
		}
		if e := localservice.Ensure(cmd.Context(), s.ConfigPath); e != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "Local credentials are ready. The optional agent could not start; run 'sshm service install' to configure startup.")
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Local credential service is ready. Run 'sshm service install' to start it at login.")
		return nil
	}}
	setup.Flags().Bool("ask-passphrases", false, "prompt for known legacy SSH key passphrases or passwords; empty input skips")
	service.AddCommand(setup)
	var supervise bool
	run := &cobra.Command{Use: "run", Short: "Run the local service in the foreground", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		background := func(ctx context.Context) { runStoredCloudSync(ctx, configPath()) }
		if supervise {
			return localservice.RunSupervised(ctx, localstore.New(configPath()), background)
		}
		return localservice.Run(ctx, localstore.New(configPath()), background)
	}}
	run.Flags().BoolVar(&supervise, "supervise", false, "wait for an existing service before taking over")
	_ = run.Flags().MarkHidden("supervise")
	service.AddCommand(run)
	var system bool
	install := &cobra.Command{Use: "install", Short: "Start the local service at login", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		binary, e := os.Executable()
		if e != nil {
			return e
		}
		if e = localservice.Install(configPath(), binary, system); e != nil {
			return e
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Local service startup installed.")
		return nil
	}}
	install.Flags().BoolVar(&system, "system", false, "install system-wide (unsupported; credentials belong to a user)")
	service.AddCommand(install)
	service.AddCommand(&cobra.Command{Use: "status", Short: "Show local service status without credentials", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(localservice.Status(configPath()))
	}})
	service.AddCommand(&cobra.Command{Use: "lock", Short: "Persistently lock local credentials", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if e := localstore.New(configPath()).Lock(cmd.Context()); e != nil {
			return e
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Local credentials locked.")
		return nil
	}})
	service.AddCommand(&cobra.Command{Use: "unlock", Short: "Verify device protection and unlock local credentials", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if e := terminal(cmd); e != nil {
			return e
		}
		if e := localstore.New(configPath()).Unlock(cmd.Context()); e != nil {
			return e
		}
		// Agent availability is optional for CLI/MCP SSH, whose resolver opens the
		// store directly. Starting it must not turn successful unlock into failure.
		_ = localservice.Ensure(cmd.Context(), configPath())
		fmt.Fprintln(cmd.OutOrStdout(), "Local credentials unlocked.")
		return nil
	}})
	return service
}
