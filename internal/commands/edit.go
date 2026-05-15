package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/spf13/cobra"
)

func newEditCmd() *cobra.Command {
	var sets []string
	c := &cobra.Command{
		Use:   "edit <alias> --set field=value [--set ...]",
		Short: "Update fields on an existing server",
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
			for _, kv := range sets {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("invalid --set %q (expected key=value)", kv)
				}
				if err := applyField(s, strings.TrimSpace(k), strings.TrimSpace(v)); err != nil {
					return err
				}
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "updated %q\n", args[0]); err != nil {
				return err
			}
			return nil
		},
	}
	c.Flags().StringArrayVar(&sets, "set", nil, "field=value (repeatable). Fields: host, port, user, auth, key_path, label, group, notes")
	return c
}

func applyField(srv *config.Server, field, val string) error {
	switch field {
	case "host":
		srv.Host = val
	case "port":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("port must be int")
		}
		srv.Port = n
	case "user":
		srv.User = val
	case "auth":
		srv.Auth = val
	case "key_path":
		srv.KeyPath = val
	case "label":
		srv.Label = val
	case "group":
		srv.Group = val
	case "notes":
		srv.Notes = val
	default:
		return fmt.Errorf("unsupported field %q", field)
	}
	return nil
}
