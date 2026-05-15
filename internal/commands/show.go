package commands

import (
	"fmt"
	"io"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
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
			renderServerDetail(cmd.OutOrStdout(), args[0], s)
			return nil
		},
	}
}

func renderServerDetail(w io.Writer, alias string, s *config.Server) {
	fmt.Fprintf(w, "Alias        %s\n", alias)
	fmt.Fprintf(w, "Label        %s\n", s.Label)
	fmt.Fprintf(w, "Host         %s\n", s.Host)
	fmt.Fprintf(w, "Port         %d\n", defaultInt(s.Port, 22))
	fmt.Fprintf(w, "User         %s\n", s.User)
	fmt.Fprintf(w, "Auth         %s\n", s.Auth)
	if s.KeyPath != "" {
		fmt.Fprintf(w, "Key          %s\n", s.KeyPath)
	}
	if len(s.Tags) > 0 {
		fmt.Fprintf(w, "Tags         %s\n", strings.Join(s.Tags, ", "))
	}
	if s.Group != "" {
		fmt.Fprintf(w, "Group        %s\n", s.Group)
	}
	if s.Notes != "" {
		fmt.Fprintf(w, "Notes        %s\n", s.Notes)
	}
	if s.InitState != "" {
		fmt.Fprintf(w, "Init state   %s\n", s.InitState)
	}
	if s.LastStatus != "" {
		fmt.Fprintf(w, "Last status  %s\n", s.LastStatus)
	}
	if !s.LastSeen.IsZero() {
		fmt.Fprintf(w, "Last seen    %s\n", s.LastSeen.Format("2006-01-02 15:04:05 MST"))
	}
}

func defaultInt(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}
