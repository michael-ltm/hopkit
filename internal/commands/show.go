package commands

import (
	"fmt"
	"io"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/spf13/cobra"
)

func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <alias>",
		Short: "Show details for one server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			s, err := resolveServer(cfg, args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{args[0]: s})
			}
			if err := renderServerDetail(cmd.OutOrStdout(), args[0], s); err != nil {
				return err
			}
			return nil
		},
	}
}

func renderServerDetail(w io.Writer, alias string, s *config.Server) error {
	lines := []struct {
		label string
		val   string
		show  bool
	}{
		{"Alias", alias, true},
		{"Label", s.Label, true},
		{"Description", config.EffectiveDescription(s), config.EffectiveDescription(s) != ""},
		{"Platform", s.Platform, s.Platform != ""},
		{"Host", s.Host, true},
		{"Port", fmt.Sprintf("%d", defaultInt(s.Port, 22)), true},
		{"User", s.User, true},
		{"Auth", s.Auth, true},
		{"Key", s.KeyPath, s.KeyPath != ""},
		{"Tags", strings.Join(s.Tags, ", "), len(s.Tags) > 0},
		{"Group", s.Group, s.Group != ""},
		{"Notes", s.Notes, s.Notes != ""},
		{"Init state", s.InitState, s.InitState != ""},
		{"Last status", s.LastStatus, s.LastStatus != ""},
		{"Cleanup", "protected", s.CleanupProtected},
	}
	for _, l := range lines {
		if !l.show {
			continue
		}
		if _, err := fmt.Fprintf(w, "%-12s %s\n", l.label, ui.SanitizeTerminalText(l.val)); err != nil {
			return err
		}
	}
	if !s.LastSeen.IsZero() {
		if _, err := fmt.Fprintf(w, "%-12s %s\n", "Last seen", s.LastSeen.Format("2006-01-02 15:04:05 MST")); err != nil {
			return err
		}
	}
	if !s.LastChecked.IsZero() {
		if _, err := fmt.Fprintf(w, "%-12s %s\n", "Last check", s.LastChecked.Format("2006-01-02 15:04:05 MST")); err != nil {
			return err
		}
	}
	if !s.LastUsed.IsZero() {
		if _, err := fmt.Fprintf(w, "%-12s %s\n", "Last used", s.LastUsed.Format("2006-01-02 15:04:05 MST")); err != nil {
			return err
		}
	}
	if !s.CreatedAt.IsZero() {
		if _, err := fmt.Fprintf(w, "%-12s %s\n", "Created", s.CreatedAt.Format("2006-01-02 15:04:05 MST")); err != nil {
			return err
		}
	}
	if !s.IdentityChangedAt.IsZero() {
		if _, err := fmt.Fprintf(w, "%-12s %s\n", "Identity changed", s.IdentityChangedAt.Format("2006-01-02 15:04:05 MST")); err != nil {
			return err
		}
	}
	return nil
}

func defaultInt(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}
