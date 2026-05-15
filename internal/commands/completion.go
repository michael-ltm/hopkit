package commands

import (
	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	c := &cobra.Command{
		Use:                   "completion {bash|zsh|fish|powershell}",
		Short:                 "Emit shell completion script",
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return cmd.Root().GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletion(cmd.OutOrStdout())
			default:
				// ValidArgs + OnlyValidArgs guard the entry point; this is unreachable.
				return nil
			}
		},
	}
	return c
}
