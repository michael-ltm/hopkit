package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

const (
	passwordPlatformAuto    = "auto"
	passwordPlatformPOSIX   = "posix"
	passwordPlatformWindows = "windows"
)

func newPasswordCmd() *cobra.Command {
	var platform string
	command := &cobra.Command{
		Use:   "password <alias>",
		Short: "Change a remote account password in a direct terminal session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			server, err := resolveServer(cfg, args[0])
			if err != nil {
				return err
			}
			confirmed, err := confirmExactAlias(cmd, args[0], "change the remote login password")
			if err != nil {
				return err
			}
			if !confirmed {
				fmt.Fprintln(cmd.OutOrStdout(), "aborted")
				return nil
			}
			return changeRemotePassword(server, platform, configPath())
		},
	}
	command.Flags().StringVar(&platform, "platform", passwordPlatformAuto, "remote platform: auto|posix|windows")
	return command
}

func changeRemotePassword(server *config.Server, platform, activeConfigPath string) error {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" {
		platform = passwordPlatformAuto
	}
	if _, err := passwordCommand(platform); err != nil && platform != passwordPlatformAuto {
		return err
	}

	client, err := dialInteractive(server, false, activeConfigPath)
	if err != nil {
		return err
	}
	defer client.Close()

	if platform == passwordPlatformAuto {
		platform, err = detectPasswordPlatform(client)
		if err != nil {
			return err
		}
	}
	remoteCommand, err := passwordCommand(platform)
	if err != nil {
		return err
	}
	return client.AttachInteractiveCommand(remoteCommand)
}

func detectPasswordPlatform(client *sshpkg.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if result, err := client.Exec(ctx, "uname -s"); err == nil && result.ExitCode == 0 && strings.TrimSpace(result.Stdout) != "" {
		return passwordPlatformPOSIX, nil
	}
	ctxWindows, cancelWindows := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelWindows()
	if result, err := client.Exec(ctxWindows, `powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$PSVersionTable.PSVersion.Major"`); err == nil && result.ExitCode == 0 {
		return passwordPlatformWindows, nil
	}
	return "", fmt.Errorf("could not detect the remote password command; retry with --platform posix or --platform windows")
}

func passwordCommand(platform string) (string, error) {
	switch platform {
	case passwordPlatformPOSIX:
		return "passwd", nil
	case passwordPlatformWindows:
		return `powershell.exe -NoLogo -NoProfile -Command "net.exe user $env:USERNAME *"`, nil
	default:
		return "", fmt.Errorf("platform must be auto, posix, or windows")
	}
}
