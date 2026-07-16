package commands

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

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
	}
	c := &cobra.Command{
		Use:   "add [--quick alias user@host[:port]]",
		Short: "Add a new server (interactive wizard, or non-interactive --quick)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			if quick.alias != "" {
				return addQuick(cmd, cfg, quick.alias, quick.user, quick.host, quick.port, quick.keyPath, quick.description, quick.tags, quick.group)
			}
			return addWizard(cmd, cfg)
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
	return c
}

func addQuick(cmd *cobra.Command, cfg *config.Config, alias, user, host string, port int, keyPath, description, tags, group string) error {
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
	if err := validateMetadataFields("", description, tagList, group, ""); err != nil {
		return err
	}
	srv := &config.Server{
		Host: host, Port: port, User: user, Auth: config.AuthKey, KeyPath: keyPath,
		Description: description, Tags: tagList, Group: group,
	}
	if keyPath == "" {
		srv.Auth = config.AuthAgent
	}
	cfg.Servers[alias] = srv
	if err := saveConfig(cfg); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "added %q\n", alias); err != nil {
		return err
	}
	return nil
}

func addWizard(cmd *cobra.Command, cfg *config.Config) error {
	existing := make([]string, 0, len(cfg.Servers))
	for k := range cfg.Servers {
		existing = append(existing, k)
	}
	in, err := wizard.RunAdd(existing)
	if err != nil {
		return err
	}
	if err := validateMetadataFields("", in.Description, splitTags(in.Tags), in.Group, ""); err != nil {
		return err
	}

	port, _ := strconv.Atoi(in.Port)
	srv := &config.Server{
		Host: in.Host, Port: port, User: in.User, Auth: in.Auth,
		KeyPath: in.KeyPath, Group: in.Group, Description: in.Description,
		Tags: splitTags(in.Tags),
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

	cfg.Servers[in.Alias] = srv
	if cfg.Default == "" {
		cfg.Default = in.Alias
	}
	if err := saveConfig(cfg); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "added %q\n", in.Alias); err != nil {
		return err
	}

	if in.TestAfter {
		r := status.Probe(context.Background(), srv, 0)
		if r.Reachable {
			fmt.Fprintf(cmd.OutOrStdout(), "test: reachable in %s\n", r.Latency)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "test: unreachable — %s\n", r.Error)
		}
	}

	if in.CopyIDAfter && srv.Auth == config.AuthKey && srv.KeyPath != "" {
		fmt.Fprintln(cmd.OutOrStdout(), "copy-id: run `sshm copy-id "+in.Alias+"` (will prompt for password once)")
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
