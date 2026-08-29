package wizard

import (
	"errors"
	"io"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/config"
)

// PairInput is the minimal information the controller needs before the target
// reports its actual username and platform.
type PairInput struct {
	Alias       string
	Host        string
	Port        string
	Platform    string
	Description string
	Tags        string
	Group       string
}

// RunPair renders the guided one-line pairing form.
func RunPair(existingAliases []string, input io.Reader, output io.Writer) (*PairInput, error) {
	in := &PairInput{Port: "22", Platform: config.PlatformWindows}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Server name / alias").Description("Example: office-pc").Value(&in.Alias).
				Validate(func(value string) error {
					if err := ValidateAlias(value); err != nil {
						return err
					}
					for _, alias := range existingAliases {
						if alias == value {
							return errors.New("alias already exists; run `sshm pair <alias>` to repair it")
						}
					}
					return nil
				}),
			huh.NewInput().Title("Server address / IP").Value(&in.Host).Validate(ValidateHost),
			huh.NewInput().Title("SSH port").Description("Press Enter for 22").Value(&in.Port).
				Validate(validateOptionalDefaultPort),
			huh.NewSelect[string]().Title("Target system").Description("Windows is selected by default").Options(
				huh.NewOption("Windows", config.PlatformWindows),
				huh.NewOption("Linux", config.PlatformLinux),
				huh.NewOption("macOS", config.PlatformMacOS),
				huh.NewOption("Not sure (show both commands)", ""),
			).Value(&in.Platform),
		),
		huh.NewGroup(
			huh.NewInput().Title("Description / purpose").Description("Optional; never put passwords or tokens here").Value(&in.Description).
				Validate(config.ValidateDescription),
			huh.NewInput().Title("Tags (comma separated)").Value(&in.Tags),
			huh.NewInput().Title("Group").Value(&in.Group),
		),
	).WithInput(input).WithOutput(output)
	if err := form.Run(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Port) == "" {
		in.Port = "22"
	}
	return in, nil
}

// RunPairPlatform asks which target-side command should be generated. It is
// shared by new pairing, pair <existing-alias>, and inventory repair.
func RunPairPlatform(current string, input io.Reader, output io.Writer) (string, error) {
	platform := current
	if platform != config.PlatformWindows && platform != config.PlatformLinux && platform != config.PlatformMacOS {
		platform = config.PlatformWindows
	}
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("Target system").Description("Choose which one-line command to generate").Options(
			huh.NewOption("Windows", config.PlatformWindows),
			huh.NewOption("Linux", config.PlatformLinux),
			huh.NewOption("macOS", config.PlatformMacOS),
			huh.NewOption("Not sure (show both commands)", ""),
		).Value(&platform),
	)).WithInput(input).WithOutput(output)
	if err := form.Run(); err != nil {
		return "", err
	}
	return platform, nil
}

// RunCallbackHost keeps VPN/TUN route failures inside the guided workflow.
func RunCallbackHost(input io.Reader, output io.Writer, validate func(string) error) (string, error) {
	value := ""
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Controller address reachable from the target").
			Description("Enter this computer's Tailscale/LAN hostname or IP (for example 100.x or 192.168.x)").
			Value(&value).
			Validate(func(candidate string) error {
				candidate = strings.TrimSpace(candidate)
				if candidate == "" {
					return errors.New("a target-reachable private address is required")
				}
				return validate(candidate)
			}),
	)).WithInput(input).WithOutput(output)
	if err := form.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func validateOptionalDefaultPort(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return ValidatePort(value)
}
