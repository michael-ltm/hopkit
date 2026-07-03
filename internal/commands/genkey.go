package commands

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/keystore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func newGenKeyCmd() *cobra.Command {
	var path string
	var noEncrypt bool
	c := &cobra.Command{
		Use:   "gen-key <alias>",
		Short: "Generate an encrypted ed25519 keypair for an alias and update its key_path",
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
			actualPath := path
			if actualPath == "" {
				actualPath = filepath.Join("~", ".ssh", "id_ed25519_"+args[0])
			}
			expanded, err := sshpkg.ExpandHome(actualPath)
			if err != nil {
				return err
			}

			var passphrase string
			if !noEncrypt {
				passphrase, err = keys.RandomPassphrase()
				if err != nil {
					return err
				}
			}
			pub, err := keys.GenerateED25519Encrypted(expanded, args[0]+"@sshm", passphrase)
			if err != nil {
				return err
			}

			var recoveryPath string
			var store keystore.Result
			if passphrase != "" {
				// Best-effort: the encrypted key on disk is the primary
				// deliverable and is valid regardless of agent/keychain
				// availability (e.g. a headless host with no ssh-agent), so
				// a keystore failure must not fail gen-key or orphan the key.
				store = keystore.BestEffort(keystore.StoreAndLoad(expanded, passphrase))

				recoveryPath, err = keys.WriteRecovery(expanded, passphrase)
				if err != nil {
					keys.RemoveGenerated(expanded)
					return fmt.Errorf("write recovery for %s: %w", expanded, err)
				}
			}

			s.KeyPath = actualPath
			if err := saveConfig(cfg); err != nil {
				keys.RemoveGenerated(expanded)
				return fmt.Errorf("save config after generating %s: %w", expanded, err)
			}

			if flagJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"alias":         args[0],
					"key_path":      expanded,
					"public_key":    strings.TrimSpace(pub),
					"encrypted":     passphrase != "",
					"persisted":     store.Persisted,
					"recovery_file": recoveryPath,
				})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, expanded)
			fmt.Fprintln(out, pub)
			if passphrase != "" {
				fmt.Fprintf(out, "\nPassphrase (save to your password manager): %s\n", passphrase)
				fmt.Fprintf(out, "Recovery file (delete after saving): %s\n", recoveryPath)
				if store.Persisted {
					fmt.Fprintln(out, "Stored in keychain — you won't be prompted again.")
				} else if store.Note != "" {
					fmt.Fprintf(out, "Note: %s\n", store.Note)
				}
			}
			return nil
		},
	}
	c.Flags().StringVarP(&path, "path", "p", "", "key path (default ~/.ssh/id_ed25519_<alias>)")
	c.Flags().BoolVar(&noEncrypt, "no-encrypt", false, "generate an unencrypted key (not recommended)")
	return c
}
