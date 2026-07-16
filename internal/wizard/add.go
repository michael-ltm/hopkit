// Package wizard implements interactive forms for sshm add/edit.
package wizard

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/config"
)

var aliasRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// ValidateAlias enforces lowercase, no spaces, allowed punctuation only.
func ValidateAlias(a string) error {
	if a == "" {
		return errors.New("alias cannot be empty")
	}
	if !aliasRE.MatchString(a) {
		return errors.New("alias must be lowercase letters, digits, '-', '_' or '.' (must start alnum)")
	}
	return nil
}

// ValidateHost rejects empty strings; everything else is accepted (the
// network layer is the authoritative validator).
func ValidateHost(h string) error {
	if strings.TrimSpace(h) == "" {
		return errors.New("host cannot be empty")
	}
	if strings.ContainsAny(h, "\x00\r\n") {
		return errors.New("host must be a single line")
	}
	return nil
}

// ValidatePort accepts integers in [1, 65535].
func ValidatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil {
		return fmt.Errorf("port must be a number")
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port must be in 1..65535")
	}
	return nil
}

// AddInput is the user-collected form result.
type AddInput struct {
	Alias       string
	Host        string
	Port        string
	User        string
	Auth        string
	KeyPath     string
	GenerateKey bool
	Description string
	Tags        string
	Group       string
	TestAfter   bool
	CopyIDAfter bool
}

// RunAdd renders the form and blocks until the user confirms. Returns a
// fully populated AddInput, or an error if the user cancels.
//
// existingAliases is used to prevent collisions.
func RunAdd(existingAliases []string) (*AddInput, error) {
	in := &AddInput{Port: "22", Auth: config.AuthKey, TestAfter: true}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Alias").Value(&in.Alias).
				Validate(func(s string) error {
					if err := ValidateAlias(s); err != nil {
						return err
					}
					for _, a := range existingAliases {
						if a == s {
							return errors.New("alias already exists")
						}
					}
					return nil
				}),
			huh.NewInput().Title("Host / IP").Value(&in.Host).Validate(ValidateHost),
			huh.NewInput().Title("Port").Value(&in.Port).Validate(ValidatePort),
			huh.NewInput().Title("User").Value(&in.User).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return errors.New("user cannot be empty")
				}
				return nil
			}),
			huh.NewSelect[string]().Title("Auth method").Options(
				huh.NewOption("Use existing key", config.AuthKey),
				huh.NewOption("Generate new ed25519 key", "generate"),
				huh.NewOption("Password", config.AuthPassword),
				huh.NewOption("ssh-agent", config.AuthAgent),
			).Value(&in.Auth),
		),
		huh.NewGroup(
			huh.NewInput().Title("Key path (used or generated)").Value(&in.KeyPath),
		).WithHideFunc(func() bool {
			return in.Auth == config.AuthPassword || in.Auth == config.AuthAgent
		}),
		huh.NewGroup(
			huh.NewInput().Title("Description / purpose").Description("Helps people and AI choose the right server").Value(&in.Description).
				Validate(config.ValidateDescription),
			huh.NewInput().Title("Tags (comma separated)").Value(&in.Tags),
			huh.NewInput().Title("Group").Value(&in.Group),
			huh.NewConfirm().Title("Test connection after save?").Value(&in.TestAfter),
			huh.NewConfirm().Title("Push public key to remote now (copy-id)?").Value(&in.CopyIDAfter),
		),
	)
	if err := form.Run(); err != nil {
		return nil, err
	}
	if in.Auth == "generate" {
		in.GenerateKey = true
		in.Auth = config.AuthKey
	}
	return in, nil
}
