package commands

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/keystore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type provisionSteps struct {
	genKey func() (string, error)
	copyID func(password string) error
	test   func() error
	harden func() error
}

// runProvision executes the onboarding steps in order and refuses to harden
// unless the connectivity test passed. password prompting happens in RunE.
func runProvision(steps provisionSteps, doHarden bool, keyConfirmed *bool) error {
	if _, err := steps.genKey(); err != nil {
		return fmt.Errorf("gen-key: %w", err)
	}
	if err := steps.copyID(""); err != nil {
		return fmt.Errorf("copy-id: %w", err)
	}
	if err := steps.test(); err != nil {
		return fmt.Errorf("connectivity test: %w", err)
	}
	if keyConfirmed != nil {
		*keyConfirmed = true
	}
	if doHarden {
		if err := steps.harden(); err != nil {
			return fmt.Errorf("harden: %w", err)
		}
	}
	return nil
}

func newProvisionCmd() *cobra.Command {
	var path string
	var doHarden bool
	c := &cobra.Command{
		Use:   "provision <alias>",
		Short: "Securely onboard an existing alias: encrypted key, install, test, optional harden",
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

			// Read the server password once, up front (needed by copy-id).
			fmt.Fprintf(cmd.ErrOrStderr(), "Password for %s@%s: ", s.User, s.Host)
			pw, err := term.ReadPassword(0)
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer func() {
				for i := range pw {
					pw[i] = 0
				}
			}()

			steps := provisionSteps{
				genKey: func() (string, error) {
					passphrase, gerr := keys.RandomPassphrase()
					if gerr != nil {
						return "", gerr
					}
					pub, gerr := keys.GenerateED25519Encrypted(expanded, args[0]+"@sshm", passphrase)
					if gerr != nil {
						return "", gerr
					}
					// In-memory only: the test step below needs s.Auth/s.KeyPath set
					// to actually exercise key auth. Persisting to disk happens later
					// in RunE, only after copy-id and the connectivity test have
					// confirmed the key works (see keyConfirmed in runProvision).
					s.KeyPath = actualPath
					s.Auth = config.AuthKey
					store, serr := keystore.StoreAndLoad(expanded, passphrase)
					if serr != nil {
						return "", serr
					}
					rp, serr := keys.WriteRecovery(expanded, passphrase)
					if serr != nil {
						return "", serr
					}
					fmt.Fprintf(cmd.OutOrStdout(), "Passphrase (save to your password manager): %s\nRecovery file: %s\n", passphrase, rp)
					if !store.Persisted && store.Note != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "Note: %s\n", store.Note)
					}
					return pub, nil
				},
				copyID: func(string) error {
					return keys.CopyID(context.Background(), s, string(pw), expanded)
				},
				test: func() error {
					cli, terr := sshpkg.Dial(s, sshpkg.BuildOpts{})
					if terr != nil {
						return terr
					}
					return cli.Close()
				},
				harden: func() error {
					return hardenDisablePassword(context.Background(), s)
				},
			}
			var confirmed bool
			err = runProvision(steps, doHarden, &confirmed)
			if confirmed {
				// Key auth was confirmed by the connectivity test, so persist
				// the alias as key-auth even if a later --harden step failed:
				// key auth itself is verified working, only hardening isn't.
				if serr := saveConfig(cfg); serr != nil {
					return fmt.Errorf("save config: %w", serr)
				}
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "provisioned: key auth working"+hardenedSuffix(doHarden))
			return nil
		},
	}
	c.Flags().StringVarP(&path, "path", "p", "", "key path (default ~/.ssh/id_ed25519_<alias>)")
	c.Flags().BoolVar(&doHarden, "harden", false, "after key auth works, disable password login on the server")
	return c
}

func hardenedSuffix(h bool) string {
	if h {
		return "; password login disabled"
	}
	return ""
}

// hardenDisablePassword installs a drop-in that disables password auth, after
// validating with `sshd -t` so a bad config can never lock the user out.
//
// internal/bootstrap.Run deliberately does NOT touch sshd settings (it only
// installs baseline tooling like fail2ban), so there is no existing reusable
// helper for this step — this is a new, minimal implementation.
func hardenDisablePassword(ctx context.Context, s *config.Server) error {
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return fmt.Errorf("dial for harden: %w", err)
	}
	defer cli.Close()
	cmd := `set -e; f=/etc/ssh/sshd_config.d/99-sshm-key-only.conf; ` +
		`printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > "$f"; ` +
		`sshd -t && (systemctl reload sshd 2>/dev/null || systemctl reload ssh || service ssh reload)`
	res, err := cli.Exec(ctx, cmd)
	if err != nil {
		return fmt.Errorf("harden exec: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("harden exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}
