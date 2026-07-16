package commands

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/status"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	managerAdd  = "::add"
	managerQuit = "::quit"

	actionShow        = "show"
	actionConnect     = "connect"
	actionTest        = "test"
	actionDescription = "description"
	actionPassword    = "password"
	actionDefault     = "default"
	actionDelete      = "delete"
	actionBack        = "back"
)

type fdProvider interface {
	Fd() uintptr
}

func commandHasTerminal(cmd *cobra.Command) bool {
	input, inputOK := cmd.InOrStdin().(fdProvider)
	output, outputOK := cmd.ErrOrStderr().(fdProvider)
	return inputOK && outputOK && term.IsTerminal(int(input.Fd())) && term.IsTerminal(int(output.Fd()))
}

func runServerManager(cmd *cobra.Command) error {
	for {
		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}
		choice, err := chooseServer(cmd, cfg)
		if errors.Is(err, huh.ErrUserAborted) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case managerQuit:
			return nil
		case managerAdd:
			if err := addWizard(cmd, cfg); err != nil {
				if errors.Is(err, huh.ErrUserAborted) {
					continue
				}
				return err
			}
		default:
			removed, err := runServerActions(cmd, choice)
			if errors.Is(err, huh.ErrUserAborted) {
				continue
			}
			if err != nil {
				return err
			}
			if removed {
				continue
			}
		}
	}
}

func chooseServer(cmd *cobra.Command, cfg *config.Config) (string, error) {
	aliases := make([]string, 0, len(cfg.Servers))
	for alias, server := range cfg.Servers {
		if server != nil {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	options := make([]huh.Option[string], 0, len(aliases)+2)
	for _, alias := range aliases {
		options = append(options, huh.NewOption(serverChoiceLabel(alias, cfg.Servers[alias]), alias))
	}
	options = append(options,
		huh.NewOption("＋ Add server", managerAdd),
		huh.NewOption("Exit", managerQuit),
	)
	choice := managerAdd
	if len(aliases) > 0 {
		choice = aliases[0]
	}
	height := len(options)
	if height > 12 {
		height = 12
	}
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("SSH servers").
			Description("↑/↓ select · Enter open · / search · Esc back").
			Options(options...).
			Value(&choice).
			Height(height),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	return choice, form.Run()
}

func serverChoiceLabel(alias string, server *config.Server) string {
	description := strings.Join(strings.Fields(ui.SanitizeTerminalText(config.EffectiveDescription(server))), " ")
	if description == "" {
		description = "no description"
	}
	if runes := []rune(description); len(runes) > 54 {
		description = string(runes[:53]) + "…"
	}
	return fmt.Sprintf("%-18s  %s  [%s@%s]",
		ui.SanitizeTerminalText(alias), description,
		ui.SanitizeTerminalText(server.User), ui.SanitizeTerminalText(server.Host))
}

func runServerActions(cmd *cobra.Command, alias string) (bool, error) {
	for {
		cfg, _, err := loadConfig()
		if err != nil {
			return false, err
		}
		server, ok := cfg.Servers[alias]
		if !ok || server == nil {
			return true, nil
		}
		action, err := chooseServerAction(cmd, alias, server, cfg.Default == alias)
		if err != nil {
			return false, err
		}
		switch action {
		case actionBack:
			return false, nil
		case actionShow:
			if err := renderServerDetail(cmd.OutOrStdout(), alias, server); err != nil {
				return false, err
			}
		case actionConnect:
			if err := connect(server, false, configPath()); err != nil {
				return false, err
			}
		case actionTest:
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			result := status.Probe(ctx, server, 10*time.Second)
			cancel()
			if result.Reachable {
				fmt.Fprintf(cmd.OutOrStdout(), "%s reachable in %s\n", alias, result.Latency)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s unreachable: %s\n", alias, result.Error)
			}
		case actionDescription:
			if err := editServerDescription(cmd, alias, config.EffectiveDescription(server)); err != nil {
				return false, err
			}
		case actionPassword:
			confirmed, err := confirmExactAlias(cmd, alias, "change the remote login password")
			if err != nil {
				return false, err
			}
			if !confirmed {
				fmt.Fprintln(cmd.OutOrStdout(), "aborted")
				continue
			}
			if err := changeRemotePassword(server, passwordPlatformAuto, configPath()); err != nil {
				return false, err
			}
		case actionDefault:
			if err := config.Update(configPath(), func(latest *config.Config) error {
				if _, exists := latest.Servers[alias]; !exists {
					return fmt.Errorf("unknown server %q", alias)
				}
				latest.Default = alias
				return nil
			}); err != nil {
				return false, err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "default server set to %q\n", alias)
		case actionDelete:
			confirmed, err := confirmExactAlias(cmd, alias, "remove this server")
			if err != nil {
				return false, err
			}
			if !confirmed {
				fmt.Fprintln(cmd.OutOrStdout(), "aborted")
				continue
			}
			if err := removeServer(alias); err != nil {
				return false, err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %q\n", alias)
			return true, nil
		}
	}
}

func chooseServerAction(cmd *cobra.Command, alias string, server *config.Server, isDefault bool) (string, error) {
	defaultLabel := "Set as default"
	if isDefault {
		defaultLabel = "Default server (selected)"
	}
	action := actionShow
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title(ui.SanitizeTerminalText(alias)).
			Description(ui.SanitizeTerminalText(config.EffectiveDescription(server))).
			Options(
				huh.NewOption("Show details", actionShow),
				huh.NewOption("Connect", actionConnect),
				huh.NewOption("Test reachability", actionTest),
				huh.NewOption("Add / edit description", actionDescription),
				huh.NewOption("Change remote login password", actionPassword),
				huh.NewOption(defaultLabel, actionDefault),
				huh.NewOption("Delete server", actionDelete),
				huh.NewOption("Back", actionBack),
			).
			Value(&action).
			Height(10),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	return action, form.Run()
}

func editServerDescription(cmd *cobra.Command, alias, current string) error {
	description := ui.SanitizeTerminalText(current)
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Server description").
			Description("Purpose, OS, installed tools, constraints; never put passwords or tokens here").
			Value(&description).
			Validate(validateDescription),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	if err := form.Run(); err != nil {
		return err
	}
	description = strings.TrimSpace(description)
	if err := config.Update(configPath(), func(cfg *config.Config) error {
		server, ok := cfg.Servers[alias]
		if !ok || server == nil {
			return fmt.Errorf("unknown server %q", alias)
		}
		server.Description = description
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "updated description for %q\n", alias)
	return nil
}

func removeServer(alias string) error {
	return config.Update(configPath(), func(cfg *config.Config) error {
		if _, ok := cfg.Servers[alias]; !ok {
			return fmt.Errorf("unknown server %q", alias)
		}
		if projects := config.ProjectsUsingServer(cfg, alias); len(projects) > 0 {
			return fmt.Errorf("server %q is used by project profiles: %s; update those profiles first", alias, strings.Join(projects, ", "))
		}
		delete(cfg.Servers, alias)
		if cfg.Default == alias {
			cfg.Default = ""
		}
		return nil
	})
}
