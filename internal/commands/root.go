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
)

// NewRoot constructs the cobra root command with all subcommands attached.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "sshm",
		Short:         "SSH connection manager",
		Long:          "sshm — a pretty, AI-friendly SSH connection manager.\nSee https://github.com/michael-ltm/sshm for docs.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&flagJSON, "json", false, "emit JSON output (where supported)")
	root.PersistentFlags().StringVar(&flagConfigPath, "config", "", "override config.toml path")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colored output")

	root.AddCommand(
		newVersionCmd(),
		newCompletionCmd(),
		newLsCmd(),
		newShowCmd(),
		newRmCmd(),
	)
	return root
}
