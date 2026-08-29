package commands

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	"github.com/michael-ltm/sshm/internal/wizard"
	"github.com/spf13/cobra"
)

func newEditCmd() *cobra.Command {
	var sets []string
	c := &cobra.Command{
		Use:   "edit <alias> --set field=value [--set ...]",
		Short: "Update fields on an existing server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(sets) == 0 {
				return fmt.Errorf("at least one --set field=value is required (e.g., --set user=ubuntu)")
			}
			identityChangedAt := time.Now().UTC()
			if err := config.Update(configPath(), func(cfg *config.Config) error {
				s, err := resolveServer(cfg, args[0])
				if err != nil {
					return err
				}
				oldHost, oldPort, oldUser := s.Host, s.Port, s.User
				for _, kv := range sets {
					k, v, ok := strings.Cut(kv, "=")
					if !ok {
						return fmt.Errorf("invalid --set %q (expected key=value)", kv)
					}
					if err := applyField(s, strings.TrimSpace(k), strings.TrimSpace(v)); err != nil {
						return err
					}
				}
				if s.Host != oldHost || s.Port != oldPort || s.User != oldUser {
					config.ClearServerActivity(s, identityChangedAt)
				}
				return nil
			}); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "updated %q\n", args[0]); err != nil {
				return err
			}
			return nil
		},
	}
	c.Flags().StringArrayVar(&sets, "set", nil, "field=value (repeatable). Fields: host, port, user, auth, key_path, platform, label, description, tags, group, notes, cleanup_protected")
	return c
}

func applyField(srv *config.Server, field, val string) error {
	switch field {
	case "host":
		if err := wizard.ValidateHost(val); err != nil {
			return err
		}
		srv.Host = val
	case "port":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("port: %q is not a valid integer: %w", val, err)
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("port: %d out of range (1..65535)", n)
		}
		srv.Port = n
	case "user":
		if strings.TrimSpace(val) == "" || strings.ContainsAny(val, "\x00\r\n") {
			return fmt.Errorf("user must be a non-empty single line")
		}
		srv.User = val
	case "auth":
		switch val {
		case config.AuthKey, config.AuthPassword, config.AuthAgent:
			srv.Auth = val
		default:
			return fmt.Errorf("auth: %q is not one of %q/%q/%q", val,
				config.AuthKey, config.AuthPassword, config.AuthAgent)
		}
	case "key_path":
		if strings.ContainsAny(val, "\x00\r\n") {
			return fmt.Errorf("key_path must be a single line")
		}
		srv.KeyPath = val
	case "platform":
		platform, err := config.NormalizePlatform(val)
		if err != nil {
			return err
		}
		srv.Platform = platform
	case "cleanup_protected":
		value, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("cleanup_protected must be true or false")
		}
		srv.CleanupProtected = value
	case "label":
		if err := validateMetadataFields(val, "", nil, "", ""); err != nil {
			return err
		}
		srv.Label = val
	case "description", "desc":
		if err := validateMetadataFields("", val, nil, "", ""); err != nil {
			return err
		}
		srv.Description = val
	case "tags":
		tags := splitTags(val)
		if err := validateMetadataFields("", "", tags, "", ""); err != nil {
			return err
		}
		srv.Tags = tags
	case "group":
		if err := validateMetadataFields("", "", nil, val, ""); err != nil {
			return err
		}
		srv.Group = val
	case "notes":
		if err := validateMetadataFields("", "", nil, "", val); err != nil {
			return err
		}
		srv.Notes = val
	default:
		return fmt.Errorf("unsupported field %q", field)
	}
	return nil
}

func validateDescription(value string) error {
	return validateMetadataFields("", value, nil, "", "")
}

func validateMetadataFields(label, description string, tags []string, group, notes string) error {
	if err := config.ValidateServerMetadataBounds(label, description, tags, group, notes); err != nil {
		return err
	}
	values := []string{label, description, group, notes}
	values = append(values, tags...)
	for _, value := range values {
		if safety.ContainsCredentialMaterial(value) {
			return fmt.Errorf("server metadata must not contain credential material")
		}
	}
	return nil
}
