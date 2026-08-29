package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/michael-ltm/sshm/internal/status"
	"github.com/michael-ltm/sshm/internal/wizard"
	"github.com/spf13/cobra"
)

func newAddCmd() *cobra.Command {
	var quick struct {
		alias       string
		user        string
		host        string
		port        int
		keyPath     string
		description string
		tags        string
		group       string
		platform    string
	}
	c := &cobra.Command{
		Use:   "add",
		Short: "Add a new server (interactive wizard, or non-interactive --quick)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			if quick.alias != "" {
				return addQuick(cmd, cfg, quick.alias, quick.user, quick.host, quick.port, quick.keyPath, quick.description, quick.tags, quick.group, quick.platform)
			}
			return runGuidedAdd(cmd, cfg)
		},
	}
	c.Flags().StringVar(&quick.alias, "quick", "", "non-interactive: alias")
	c.Flags().StringVar(&quick.user, "user", "", "user (with --quick)")
	c.Flags().StringVar(&quick.host, "host", "", "host (with --quick)")
	c.Flags().IntVar(&quick.port, "port", 22, "port (with --quick)")
	c.Flags().StringVarP(&quick.keyPath, "identity", "i", "", "key path (with --quick)")
	c.Flags().StringVarP(&quick.description, "description", "d", "", "server purpose/description (with --quick)")
	c.Flags().StringVar(&quick.tags, "tags", "", "comma-separated discovery tags (with --quick)")
	c.Flags().StringVar(&quick.group, "group", "", "server group (with --quick)")
	c.Flags().StringVar(&quick.platform, "platform", "", "target system: windows, linux, or macos (with --quick)")
	return c
}

func addQuick(cmd *cobra.Command, cfg *config.Config, alias, user, host string, port int, keyPath, description, tags, group, platform string) error {
	if err := wizard.ValidateAlias(alias); err != nil {
		return err
	}
	if _, exists := cfg.Servers[alias]; exists {
		return fmt.Errorf("alias %q already exists", alias)
	}
	if user == "" || host == "" {
		return fmt.Errorf("--user and --host required with --quick")
	}
	if strings.ContainsAny(user, "\x00\r\n") {
		return fmt.Errorf("user must be a single line")
	}
	if err := wizard.ValidateHost(host); err != nil {
		return err
	}
	if err := wizard.ValidatePort(strconv.Itoa(port)); err != nil {
		return err
	}
	tagList := splitTags(tags)
	platform, err := config.NormalizePlatform(platform)
	if err != nil {
		return err
	}
	if err := validateMetadataFields("", description, tagList, group, ""); err != nil {
		return err
	}
	srv := &config.Server{
		Host: host, Port: port, User: user, Auth: config.AuthKey, KeyPath: keyPath,
		Description: description, Tags: tagList, Group: group, Platform: platform,
		CreatedAt: time.Now().UTC(),
	}
	if keyPath == "" {
		srv.Auth = config.AuthAgent
	}
	if err := config.Update(configPath(), func(latest *config.Config) error {
		if _, exists := latest.Servers[alias]; exists {
			return fmt.Errorf("alias %q already exists", alias)
		}
		latest.Servers[alias] = srv
		return nil
	}); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "added %q\n", alias); err != nil {
		return err
	}
	return nil
}

func runGuidedAdd(cmd *cobra.Command, cfg *config.Config) error {
	if !commandHasTerminal(cmd) {
		return fmt.Errorf("guided add requires a terminal; use `sshm pair <alias> --host <host>` or `sshm add --quick ...`")
	}
	mode := "pair"
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("How do you want to add this server?").
			Description("One-line pairing detects the username and verifies SSH automatically").
			Options(
				huh.NewOption("One-line automatic pairing (recommended)", "pair"),
				huh.NewOption("Manual record (SSH already configured)", "manual"),
			).
			Value(&mode),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr())
	if err := form.Run(); err != nil {
		return err
	}
	if mode == "pair" {
		return runPairWizard(cmd, cfg)
	}
	return addWizard(cmd, cfg)
}

func addWizard(cmd *cobra.Command, cfg *config.Config) error {
	existing := make([]string, 0, len(cfg.Servers))
	for k := range cfg.Servers {
		existing = append(existing, k)
	}
	in, err := wizard.RunAdd(existing, cmd.InOrStdin(), cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	if err := validateMetadataFields("", in.Description, splitTags(in.Tags), in.Group, ""); err != nil {
		return err
	}
	if in.Auth == config.AuthKey && !in.GenerateKey {
		expanded, err := sshpkg.ExpandHome(in.KeyPath)
		if err != nil {
			return err
		}
		info, err := os.Stat(expanded)
		if err != nil {
			return fmt.Errorf("existing private key %q is not readable: %w", expanded, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("existing private key %q is not a regular file", expanded)
		}
		if in.CopyIDAfter {
			if _, err := os.Stat(expanded + ".pub"); err != nil {
				return fmt.Errorf("copy-id needs the matching public key %q: %w", expanded+".pub", err)
			}
		}
	}

	port, _ := strconv.Atoi(in.Port)
	srv := &config.Server{
		Host: in.Host, Port: port, User: in.User, Auth: in.Auth,
		KeyPath: in.KeyPath, Group: in.Group, Description: in.Description,
		Tags: splitTags(in.Tags), Platform: in.Platform, CreatedAt: time.Now().UTC(),
	}

	// Generate key if requested.
	if in.GenerateKey {
		if srv.KeyPath == "" {
			srv.KeyPath = filepath.Join("~", ".ssh", "id_ed25519_"+in.Alias)
		}
		expanded, err := sshpkg.ExpandHome(srv.KeyPath)
		if err != nil {
			return err
		}
		pub, err := keys.GenerateED25519(expanded, in.Alias+"@sshm")
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "generated %s\n", expanded)
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", strings.TrimSpace(pub))
	}

	if err := config.Update(configPath(), func(latest *config.Config) error {
		if _, exists := latest.Servers[in.Alias]; exists {
			return fmt.Errorf("alias %q already exists", in.Alias)
		}
		latest.Servers[in.Alias] = srv
		if latest.Default == "" {
			latest.Default = in.Alias
		}
		return nil
	}); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "added %q\n", in.Alias); err != nil {
		return err
	}

	if in.TestAfter {
		r := status.Probe(context.Background(), srv, 0)
		if err := config.RecordProbes(configPath(), map[string]config.ProbeObservation{
			in.Alias: config.NewProbeObservation(srv, r.Reachable, r.ObservedAt),
		}); err != nil {
			return err
		}
		if r.Reachable {
			fmt.Fprintf(cmd.OutOrStdout(), "test: reachable in %s\n", r.Latency)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "test: unreachable — %s\n", r.Error)
		}
	}

	if in.CopyIDAfter && srv.Auth == config.AuthKey && srv.KeyPath != "" {
		fmt.Fprintln(cmd.OutOrStdout(), "Next step: run `sshm copy-id "+in.Alias+"` (it will prompt for the password once)")
	}
	return nil
}

func splitTags(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
