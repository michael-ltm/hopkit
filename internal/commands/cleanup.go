package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	cleanupmodel "github.com/michael-ltm/sshm/internal/cleanup"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/spf13/cobra"
)

func newCleanupCmd() *cobra.Command {
	var days int
	var includeUnknown bool
	var plain bool
	command := &cobra.Command{
		Use:     "cleanup",
		Aliases: []string{"prune"},
		Short:   "Review and safely remove unused server records",
		Long: `Reviews authenticated SSH usage, never just one failed reachability check.

Interactive cleanup starts with no servers selected, protects default/project/
ProxyJump/manual-protected entries, creates a private config backup before
removal, and never deletes local keys, known_hosts entries, or remote authorized
keys.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if days < 1 || days > 3650 {
				return fmt.Errorf("--days must be in 1..3650")
			}
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), cleanupmodel.Review(cfg, time.Now(), days, includeUnknown))
			}
			if plain || !commandHasTerminal(cmd) {
				return renderCleanupReport(cmd, cleanupmodel.Review(cfg, time.Now(), days, includeUnknown))
			}
			return runCleanupWizard(cmd, days, includeUnknown)
		},
	}
	command.Flags().IntVar(&days, "days", 90, "review servers unused for at least this many days")
	command.Flags().BoolVar(&includeUnknown, "include-unknown", false, "include legacy servers with no usage history")
	command.Flags().BoolVar(&plain, "plain", false, "preview candidates without opening the interactive cleaner")
	return command
}

func runCleanupWizard(cmd *cobra.Command, defaultDays int, defaultIncludeUnknown bool) error {
	days := defaultDays
	includeUnknown := defaultIncludeUnknown
	periodOptions := []huh.Option[int]{
		huh.NewOption("30 days", 30), huh.NewOption("90 days", 90),
		huh.NewOption("180 days", 180), huh.NewOption("365 days", 365),
	}
	found := false
	for _, value := range []int{30, 90, 180, 365} {
		if value == days {
			found = true
		}
	}
	if !found {
		periodOptions = append([]huh.Option[int]{huh.NewOption(fmt.Sprintf("%d days", days), days)}, periodOptions...)
	}
	policyForm := huh.NewForm(huh.NewGroup(
		huh.NewSelect[int]().Title("Unused for how long?").Options(periodOptions...).Value(&days),
		huh.NewConfirm().
			Title("Include legacy servers whose usage history is unknown?").
			Description("They will be shown for manual review, never preselected").
			Value(&includeUnknown),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	if err := policyForm.Run(); err != nil {
		return err
	}

	cfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	report := cleanupmodel.Review(cfg, time.Now(), days, includeUnknown)
	if err := renderCleanupNotes(cmd, report); err != nil {
		return err
	}
	if len(report.Candidates) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No removable server records match this review.")
		return nil
	}

	menuWidth, menuHeight := serverManagerDimensions(cmd, len(report.Candidates))
	options := make([]huh.Option[string], 0, len(report.Candidates))
	for _, entry := range report.Candidates {
		options = append(options, huh.NewOption(cleanupChoiceLabel(entry, menuWidth), entry.Alias))
	}
	selected := []string{}
	selectForm := huh.NewForm(huh.NewGroup(
		huh.NewMultiSelect[string]().
			Title("Select server records to remove").
			Description("Space toggles; nothing is selected by default; / filters").
			Options(options...).Value(&selected).Height(menuHeight),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	if err := selectForm.Run(); err != nil {
		return err
	}
	if len(selected) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No servers selected; nothing changed.")
		return nil
	}
	sort.Strings(selected)
	selectedDisplay := make([]string, len(selected))
	for index, alias := range selected {
		selectedDisplay[index] = ui.SanitizeTerminalText(alias)
	}
	confirmed := false
	confirmForm := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(fmt.Sprintf("Remove %d SSHM server record(s)?", len(selected))).
			Description(strings.Join(selectedDisplay, ", ") + "\nKeys and remote authorized_keys will not be touched.").
			Affirmative("Remove records").Negative("Cancel").Value(&confirmed),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	if err := confirmForm.Run(); err != nil {
		return err
	}
	if !confirmed {
		fmt.Fprintln(cmd.OutOrStdout(), "Cleanup cancelled; nothing changed.")
		return nil
	}

	removed, backupPath, err := removeCleanupServers(configPath(), selected, days, time.Now())
	if err != nil {
		if backupPath != "" {
			return fmt.Errorf("cleanup stopped; backup kept at %s: %w", backupPath, err)
		}
		return fmt.Errorf("cleanup stopped before changing the config: %w", err)
	}
	removedDisplay := make([]string, len(removed))
	for index, alias := range removed {
		removedDisplay[index] = ui.SanitizeTerminalText(alias)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Removed %d server record(s): %s\n", len(removed), strings.Join(removedDisplay, ", "))
	fmt.Fprintf(cmd.OutOrStdout(), "Config backup: %s\n", ui.SanitizeTerminalText(backupPath))
	fmt.Fprintln(cmd.OutOrStdout(), "Local keys, known_hosts, and remote authorized_keys were not changed.")
	return nil
}

func cleanupChoiceLabel(entry cleanupmodel.Entry, width int) string {
	reason := ui.SanitizeTerminalText(entry.Reason)
	if entry.IdleDays > 0 {
		reason = fmt.Sprintf("%s %dd", reason, entry.IdleDays)
	}
	platform := ui.SanitizeTerminalText(entry.Platform)
	if platform == "" {
		platform = "unknown system"
	}
	alias := ui.SanitizeTerminalText(entry.Alias)
	description := ui.SanitizeTerminalText(entry.Description)
	return ui.TruncateWidth(fmt.Sprintf("%-20s  %-14s  %-14s  %s", alias, platform, reason, description), width)
}

func renderCleanupReport(cmd *cobra.Command, report cleanupmodel.Report) error {
	if err := renderCleanupNotes(cmd, report); err != nil {
		return err
	}
	if len(report.Candidates) == 0 {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "No removable server records match this review.")
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Cleanup candidates (preview only, %d+ days):\n", report.OlderThanDays)
	for _, entry := range report.Candidates {
		fmt.Fprintf(cmd.OutOrStdout(), "  %-20s %-15s %s\n",
			ui.SanitizeTerminalText(entry.Alias), ui.SanitizeTerminalText(entry.Reason), cleanupAge(entry))
	}
	if !commandHasTerminal(cmd) {
		fmt.Fprintln(cmd.OutOrStdout(), "Run `sshm cleanup` in a terminal to select and remove records safely.")
	}
	return nil
}

func renderCleanupNotes(cmd *cobra.Command, report cleanupmodel.Report) error {
	if len(report.Unknown) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%d legacy server(s) have unknown usage history; enable include-unknown to review them.\n", len(report.Unknown))
	}
	if len(report.Protected) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%d matching server(s) are protected and cannot be selected:\n", len(report.Protected))
		for _, entry := range report.Protected {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-20s %s\n", ui.SanitizeTerminalText(entry.Alias),
				ui.SanitizeTerminalText(strings.Join(entry.ProtectionReasons, "; ")))
		}
	}
	return nil
}

func cleanupAge(entry cleanupmodel.Entry) string {
	if entry.Reason == cleanupmodel.ReasonHistoryUnknown {
		return "history unknown"
	}
	return fmt.Sprintf("%d days", entry.IdleDays)
}

func backupConfig(path string, now time.Time) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read config for cleanup backup: %w", err)
	}
	return backupConfigData(path, data, now)
}

func backupConfigData(path string, data []byte, now time.Time) (backup string, err error) {
	backup = path + ".backup-" + now.UTC().Format("20060102-150405.000000000")
	file, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create cleanup backup: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = os.Remove(backup)
		}
	}()
	if err := protectPrivateFile(backup); err != nil {
		return "", fmt.Errorf("protect cleanup backup: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("write cleanup backup: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync cleanup backup: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close cleanup backup: %w", err)
	}
	if err := syncParentDir(backup); err != nil {
		return "", fmt.Errorf("sync cleanup backup directory: %w", err)
	}
	complete = true
	return backup, nil
}

func removeCleanupServers(path string, aliases []string, olderThanDays int, backupAt time.Time) ([]string, string, error) {
	selected := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		selected[alias] = struct{}{}
	}
	removed := make([]string, 0, len(selected))
	backupPath := ""
	err := config.UpdateWithSource(path, func(cfg *config.Config, source []byte) error {
		review := cleanupmodel.Review(cfg, time.Now(), olderThanDays, true)
		eligible := make(map[string]struct{}, len(review.Candidates))
		for _, entry := range review.Candidates {
			eligible[entry.Alias] = struct{}{}
		}
		for alias := range selected {
			if _, exists := cfg.Servers[alias]; !exists {
				return fmt.Errorf("server %q no longer exists", alias)
			}
			if reasons := config.CleanupProtectionReasons(cfg, alias); len(reasons) > 0 {
				return fmt.Errorf("server %q became protected: %s", alias, strings.Join(reasons, "; "))
			}
			if _, ok := eligible[alias]; !ok {
				return fmt.Errorf("server %q is no longer an unused candidate", alias)
			}
		}
		var err error
		backupPath, err = backupConfigData(path, source, backupAt)
		if err != nil {
			return err
		}
		for alias := range selected {
			delete(cfg.Servers, alias)
			removed = append(removed, alias)
		}
		sort.Strings(removed)
		return nil
	})
	return removed, backupPath, err
}
