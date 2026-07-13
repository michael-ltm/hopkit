package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at link time via -ldflags; default tracks the source build.
var Version = "0.6.0"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), Version)
		},
	}
}
