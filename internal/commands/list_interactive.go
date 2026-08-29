package commands

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/status"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/michael-ltm/sshm/internal/wizard"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	managerAdd     = "::add"
	managerCleanup = "::cleanup"
	managerQuit    = "::quit"

	actionShow           = "show"
	actionPair           = "pair"
	actionConnect        = "connect"
	actionTest           = "test"
	actionDescription    = "description"
	actionPassword       = "password"
	actionDefault        = "default"
	actionDelete         = "delete"
	actionCleanupProtect = "cleanup-protect"
	actionBack           = "back"
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
	lastChoice := ""
	for {
		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}
		choice, err := chooseServer(cmd, cfg, lastChoice)
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
			if err := runGuidedAdd(cmd, cfg); err != nil {
				if errors.Is(err, huh.ErrUserAborted) {
					continue
				}
				return err
			}
		case managerCleanup:
			if err := runCleanupWizard(cmd, 90, false); err != nil {
				if errors.Is(err, huh.ErrUserAborted) {
					continue
				}
				return err
			}
		default:
			lastChoice = choice
			removed, err := runServerActions(cmd, choice)
			if errors.Is(err, huh.ErrUserAborted) {
				continue
			}
			if err != nil {
				return err
			}
			if removed {
				lastChoice = ""
				continue
			}
		}
	}
}

func chooseServer(cmd *cobra.Command, cfg *config.Config, initial string) (string, error) {
	menuWidth, menuHeight := serverManagerDimensions(cmd, len(cfg.Servers)+3)
	aliases := make([]string, 0, len(cfg.Servers))
	for alias, server := range cfg.Servers {
		if server != nil {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	options := make([]huh.Option[string], 0, len(aliases)+2)
	for _, alias := range aliases {
		options = append(options, huh.NewOption(serverChoiceLabel(alias, cfg.Servers[alias], menuWidth), alias))
	}
	options = append(options,
		huh.NewOption("＋ Add server", managerAdd),
		huh.NewOption("Review unused servers", managerCleanup),
		huh.NewOption("Exit", managerQuit),
	)
	choice := initialServerChoice(aliases, initial)
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("SSH servers").
			Description("↑/↓ select · j/k move · Enter open · / search · Esc back").
			Options(options...).
			Value(&choice).
			Height(menuHeight),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	return choice, form.Run()
}

func initialServerChoice(aliases []string, initial string) string {
	if len(aliases) == 0 {
		return managerAdd
	}
	for _, alias := range aliases {
		if alias == initial {
			return initial
		}
	}
	return aliases[0]
}

func serverManagerDimensions(cmd *cobra.Command, optionCount int) (width, height int) {
	width, rows := 100, 24
	if output, ok := cmd.ErrOrStderr().(fdProvider); ok {
		if terminalWidth, terminalRows, err := term.GetSize(int(output.Fd())); err == nil {
			if terminalWidth > 0 {
				width = terminalWidth
			}
			if terminalRows > 0 {
				rows = terminalRows
			}
		}
	}
	// Leave room for the selector glyph and huh's horizontal frame. Keeping
	// every option to one physical row prevents wrapped rows from confusing
	// the viewport's option-index/line-offset bookkeeping on narrow terminals.
	width -= 6
	if width < 20 {
		width = 20
	}
	height = rows - 6 // title, description, help/footer, and prompt
	if height < 4 {
		height = 4
	}
	if height > optionCount {
		height = optionCount
	}
	if height < 1 {
		height = 1
	}
	return width, height
}

func serverChoiceLabel(alias string, server *config.Server, maxWidth int) string {
	alias = ui.SanitizeTerminalText(alias)
	description := strings.Join(strings.Fields(ui.SanitizeTerminalText(config.EffectiveDescription(server))), " ")
	if description == "" {
		description = "no description"
	}
	user := ui.SanitizeTerminalText(server.User)
	host := ui.SanitizeTerminalText(server.Host)
	endpoint := host
	if user != "" {
		endpoint = user + "@" + host
	}
	if maxWidth < 32 {
		return ui.TruncateWidth(alias, maxWidth)
	}

	aliasWidth := 18
	if aliasWidth > maxWidth/3 {
		aliasWidth = maxWidth / 3
	}
	aliasCell := ui.PadRightWidth(alias, aliasWidth)
	endpointCell := "[" + endpoint + "]"
	endpointMax := maxWidth / 3
	if endpointMax < 16 {
		endpointMax = 16
	}
	endpointCell = ui.TruncateWidth(endpointCell, endpointMax)
	descriptionWidth := maxWidth - aliasWidth - len("    ") - lipgloss.Width(endpointCell)
	if descriptionWidth < 10 {
		return ui.TruncateWidth(fmt.Sprintf("%s  %s", aliasCell, endpointCell), maxWidth)
	}
	return ui.TruncateWidth(fmt.Sprintf("%s  %s  %s", aliasCell, ui.TruncateWidth(description, descriptionWidth), endpointCell), maxWidth)
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
		case actionPair:
			if err := runExistingPairWizard(cmd, alias, server); err != nil {
				return false, err
			}
		case actionConnect:
			if err := connect(alias, server, false, configPath()); err != nil {
				return false, err
			}
		case actionTest:
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			result := status.Probe(ctx, server, 10*time.Second)
			cancel()
			if err := config.RecordProbes(configPath(), map[string]config.ProbeObservation{
				alias: config.NewProbeObservation(server, result.Reachable, result.ObservedAt),
			}); err != nil {
				return false, err
			}
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
			if err := changeRemotePassword(alias, server, passwordPlatformAuto, configPath()); err != nil {
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
		case actionCleanupProtect:
			protected := !server.CleanupProtected
			if err := config.Update(configPath(), func(latest *config.Config) error {
				current, exists := latest.Servers[alias]
				if !exists || current == nil {
					return fmt.Errorf("unknown server %q", alias)
				}
				current.CleanupProtected = protected
				return nil
			}); err != nil {
				return false, err
			}
			if protected {
				fmt.Fprintf(cmd.OutOrStdout(), "%q is protected from cleanup\n", alias)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%q cleanup protection removed\n", alias)
			}
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
	cleanupLabel := "Protect from cleanup"
	if server.CleanupProtected {
		cleanupLabel = "Remove cleanup protection"
	}
	action := actionShow
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title(ui.SanitizeTerminalText(alias)).
			Description(ui.SanitizeTerminalText(config.EffectiveDescription(server))).
			Options(
				huh.NewOption("Show details", actionShow),
				huh.NewOption("Pair / repair SSH access", actionPair),
				huh.NewOption("Connect", actionConnect),
				huh.NewOption("Test reachability", actionTest),
				huh.NewOption("Add / edit description", actionDescription),
				huh.NewOption("Change remote login password", actionPassword),
				huh.NewOption(defaultLabel, actionDefault),
				huh.NewOption(cleanupLabel, actionCleanupProtect),
				huh.NewOption("Delete server", actionDelete),
				huh.NewOption("Back", actionBack),
			).
			Value(&action).
			Height(12),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	return action, form.Run()
}

func runExistingPairWizard(cmd *cobra.Command, alias string, server *config.Server) error {
	platform, err := wizard.RunPairPlatform(server.Platform, cmd.InOrStdin(), cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	opts := defaultPairOptions()
	opts.target = pairTargetForPlatform(platform)
	return runPairCommand(cmd, alias, opts)
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
		return config.RemoveServer(cfg, alias)
	})
}
