// Package commands wires every CLI subcommand to the cobra root.
package commands

import (
	"github.com/spf13/cobra"
)

// Global flag values, set by cobra and read by individual commands.
var (
	flagJSON       bool
	flagConfigPath string
	flagNoColor    bool
	flagRedacted   bool
)

// NewRoot constructs the cobra root command with all subcommands attached.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:              "sshm",
		Version:          Version,
		Short:            "SSH connection manager",
		Long:             "sshm — local SSH and encrypted device connections.\nRun sshm for the interactive home menu.",
		SilenceUsage:     true,
		SilenceErrors:    true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) { updateHint(cmd) },
		Args:             cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if commandHasTerminal(cmd) && !flagJSON {
				return runHome(cmd)
			}
			return cmd.Help()
		},
	}
	root.PersistentFlags().BoolVar(&flagJSON, "json", false, "emit JSON output (where supported)")
	root.PersistentFlags().StringVar(&flagConfigPath, "config", "", "override config.toml path")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colored output")
	root.PersistentFlags().BoolVar(&flagRedacted, "redacted", false, "mask secrets, IPs, and sensitive paths in JSON output")

	root.AddCommand(
		newVersionCmd(),
		newMenuCmd(),
		newSettingsCmd(),
		newCloudCmd(),
		newSyncCmd(),
		newUpdateCmd(),
		newIntegrationsCmd(),
		newCompletionCmd(),
		newLsCmd(),
		newShowCmd(),
		newRmCmd(),
		newAddCmd(),
		newEditCmd(),
		newPasswordCmd(),
		newConnectCmd(),
		newExecCmd(),
		newUploadCmd(),
		newDownloadCmd(),
		newTestCmd(),
		newInspectCmd(),
		newDoctorCmd(),
		newCopyIDCmd(),
		newGenKeyCmd(),
		newProvisionCmd(),
		newPairCmd(),
		newCleanupCmd(),
		newStatusCmd(),
		newInitCmd(),
		newMcpCmd(),
	)

	// Convenient account entry points retain the cloud subcommands and their flags.
	for _, name := range []string{"login", "logout", "devices"} {
		cloud := newCloudCmd()
		for _, child := range cloud.Commands() {
			if child.Name() == name {
				child.Flags().AddFlagSet(cloud.PersistentFlags())
				root.AddCommand(child)
				break
			}
		}
	}
	root.AddGroup(&cobra.Group{ID: "daily", Title: "Common commands:"}, &cobra.Group{ID: "account", Title: "Account and sync:"}, &cobra.Group{ID: "advanced", Title: "Advanced and automation:"})
	for _, child := range root.Commands() {
		child.GroupID = "advanced"
		switch child.Name() {
		case "menu", "ls", "connect", "add", "settings", "update", "version":
			child.GroupID = "daily"
		case "login", "logout", "devices", "sync", "cloud":
			child.GroupID = "account"
		}
	}
	return root
}
