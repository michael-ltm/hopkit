package commands

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/spf13/cobra"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func cloudSecret(cmd *cobra.Command, label string, confirm bool) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("%s requires a local interactive terminal; never put secrets in arguments or chat", label)
	}
	fmt.Fprint(cmd.ErrOrStderr(), label+": ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(cmd.ErrOrStderr(), "Repeat: ")
		again, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		defer cloudsync.Wipe(again)
		if e != nil || string(b) != string(again) {
			cloudsync.Wipe(b)
			return nil, errors.New("values do not match")
		}
	}
	return b, nil
}
func cloudOpen(cmd *cobra.Command) (*cloudsync.State, *cloudsync.Vault, func(), error) {
	path := cloudsync.StatePath(configPath())
	release, err := cloudsync.Lock(path)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := cloudsync.LoadState(path)
	if err != nil {
		release()
		return nil, nil, nil, cloudStateLoadError(err)
	}
	recoverMode, _ := cmd.Flags().GetBool("use-recovery")
	unlockLabel := "Vault unlock phrase"
	if recoverMode {
		unlockLabel = "Recovery code"
	}
	pass, err := cloudSecret(cmd, unlockLabel, false)
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	defer cloudsync.Wipe(pass)
	v, err := cloudsync.Unlock(s.Username, s.Draft, pass, recoverMode)
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	return s, v, func() { v.Close(); release() }, nil
}
func cloudState() (*cloudsync.State, func(), error) {
	path := cloudsync.StatePath(configPath())
	release, err := cloudsync.Lock(path)
	if err != nil {
		return nil, nil, err
	}
	s, err := cloudsync.LoadState(path)
	if err != nil {
		release()
		return nil, nil, cloudStateLoadError(err)
	}
	return s, release, nil
}
// confirmCloudRemoval asks whether removing a local server should also
// tombstone its cloud vault entry.
func confirmCloudRemoval(cmd *cobra.Command) (bool, error) {
	scope := "local"
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Delete scope").
			Description("This server has an encrypted cloud vault entry").
			Options(
				huh.NewOption("Local only", "local"),
				huh.NewOption("Local + cloud vault", "cloud"),
			).
			Value(&scope),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme())
	if err := form.Run(); err != nil {
		return false, err
	}
	return scope == "cloud", nil
}

// removeCloudEntry tombstones a cloud vault entry by ID (or alias fallback)
// and saves the draft locally; sshm cloud sync pushes the deletion.
func removeCloudEntry(cmd *cobra.Command, alias, cloudEntry string) error {
	s, v, close, err := cloudOpen(cmd)
	if err != nil {
		return err
	}
	defer close()
	id := cloudEntry
	if strings.TrimSpace(id) == "" {
		id = alias
	}
	e, err := v.Data.Find(id)
	if err != nil {
		return err
	}
	v.Data.Remove(e.ID)
	return s.SaveDraft(v, cloudsync.StatePath(configPath()))
}

func cloudSaveRecovery(cmd *cobra.Command, path, recovery string) error {
	// High-entropy recovery material is written directly to a protected local file,
	// never to stdout, JSON, audit output or the account web page.
	if path == "" {
		path = filepath.Join(filepath.Dir(cloudsync.StatePath(configPath())), "recovery-"+cloudsync.RandomID()+".txt")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("recovery file already exists; choose a new path")
	}
	if err := cloudsync.WritePrivate(path, []byte("SSHM recovery code. Store offline in your password manager.\n"+recovery+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Recovery code saved privately to %s. Move it to your password manager.\n", path)
	return nil
}
func newCloudCmd() *cobra.Command {
	root := &cobra.Command{Use: "cloud", Short: "Optional account and end-to-end encrypted server vault"}
	var endpoint, username, label, recoveryPath string
	root.PersistentFlags().Bool("use-recovery", false, "unlock the vault with its recovery code instead of the unlock phrase")
	root.PersistentFlags().StringVar(&endpoint, "endpoint", cloudsync.DefaultURL, "cloud HTTPS origin")
	root.PersistentFlags().StringVar(&username, "username", "", "account username (not an SSH user)")
	root.PersistentFlags().StringVar(&label, "device", "", "device label")
	root.PersistentFlags().StringVar(&recoveryPath, "recovery-file", "", "new private file for generated recovery code")
	makeAccount := func(register bool) *cobra.Command {
		var importLocal, syncLocal, noSync bool
		verb := "login"
		if register {
			verb = "register"
		}
		c := &cobra.Command{Use: verb, Short: verb + " using local terminal prompts", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if username == "" && commandHasTerminal(cmd) {
				if err := huh.NewForm(huh.NewGroup(huh.NewInput().Title(textUI("Account username", "账号用户名")).Value(&username))).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme()).Run(); err != nil {
					return err
				}
			}
			username = strings.ToLower(strings.TrimSpace(username))
			if !cloudsync.ValidAccount(username) {
				return errors.New("provide --username with 3-64 lowercase letters, digits, dots, underscores or hyphens")
			}
			if label == "" {
				label, _ = os.Hostname()
			}
			if err := cloudsync.ValidateURL(endpoint); err != nil {
				return err
			}
			path := cloudsync.StatePath(configPath())
			release, err := cloudsync.Lock(path)
			if err != nil {
				return err
			}
			defer release()
			old, oldErr := cloudsync.LoadState(path)
			if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
				return errors.New("existing cloud state cannot be read; preserve it before registering or logging in with another --config")
			}
			if oldErr == nil && (register || old.Username != username || old.URL != endpoint) && (old.Token != "" || old.Dirty || old.Pending != nil) {
				return errors.New("another cloud account or unsynced draft exists; use another --config or sync and logout first")
			}
			password, err := cloudSecret(cmd, textUI("Account password (6+ characters)", "账号密码（至少 6 个字符）"), register)
			if err != nil {
				return err
			}
			defer cloudsync.Wipe(password)
			if !cloudsync.ValidAccountPassword(password) {
				return errors.New("account password must contain 6-256 characters")
			}
			unlock, err := cloudSecret(cmd, textUI("Vault unlock phrase (different from account password, 6+ characters)", "保险库解锁口令（与账号密码不同，至少 6 个字符）"), register)
			if err != nil {
				return err
			}
			defer cloudsync.Wipe(unlock)
			if string(password) == string(unlock) {
				return errors.New("account password and vault unlock phrase must be different")
			}
			var s *cloudsync.State
			if register {
				v, recovery, err := cloudsync.NewVault(username, unlock)
				if err != nil {
					return err
				}
				defer v.Close()
				if err = cloudSaveRecovery(cmd, recoveryPath, recovery); err != nil {
					return err
				}
				s, err = cloudsync.Register(cmd.Context(), endpoint, username, label, password, v, recovery)
				if err != nil {
					return err
				}
			} else {
				device := cloudsync.RandomID()
				if oldErr == nil && old.Username == username && old.URL == endpoint {
					device = old.DeviceID
				}
				s, err = cloudsync.LoginDevice(cmd.Context(), endpoint, username, label, password, device)
				if err != nil {
					return err
				}
				v, e := cloudsync.Unlock(username, s.Draft, unlock, false)
				if e != nil {
					_ = s.Request(cmd.Context(), "DELETE", "/v1/devices/"+s.DeviceID, nil, nil)
					return e
				}
				v.Close()
				if oldErr == nil && old.Username == username && old.URL == endpoint {
					if s.Base.Revision < old.Base.Revision {
						return errors.New("cloud revision rollback detected during login")
					}
					if old.Dirty || old.Pending != nil {
						previous, e := cloudsync.Unlock(username, old.Draft, unlock, false)
						if e != nil {
							return errors.New("old unsynced draft uses different unlock material; preserve it with another --config")
						}
						previous.Close()
						s.Base = old.Base
						s.Draft = old.Draft
						s.Dirty = old.Dirty
						s.Pending = old.Pending
					}
				}
			}
			if err = s.Save(path); err != nil {
				return err
			}
			if err = s.Heartbeat(cmd.Context(), Version); err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "Account saved; device heartbeat could not be sent yet.")
			}
			if !noSync && !syncLocal {
				fmt.Fprintln(cmd.ErrOrStderr(), "Login successful. Sync cloud connections into sshm list? Credentials stay encrypted; existing local connections are preserved.")
				if importLocal {
					fmt.Fprintln(cmd.ErrOrStderr(), "This also encrypts and merges local records and configured key files (--import-local).")
				}
				syncLocal, err = askCloudSync(cmd)
				if err != nil {
					return err
				}
			}
			if syncLocal {
				v, err := cloudsync.Unlock(username, s.Draft, unlock, false)
				if err != nil {
					return err
				}
				defer v.Close()
				if err = s.Sync(cmd.Context(), v, path); err != nil {
					return err
				}
				cfg, err := config.Load(configPath())
				if err != nil {
					return err
				}
				var report cloudsync.ImportReport
				if importLocal {
					report, err = v.Data.Import(cfg, s.DeviceID, true)
				}
				if err != nil {
					return err
				}
				if err = s.SaveDraft(v, path); err != nil {
					return err
				}
				if err = s.Sync(cmd.Context(), v, path); err != nil {
					return err
				}
				if err = publishCloudInventory(cmd, s, v); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Imported and synced revision %d: %d new connections, %d matched, %d key references; %d agent-only and %d password entries need local credentials. Local configuration preserved.\n", s.Base.Revision, report.Added, report.Existing, report.Keys, report.AgentOnly, report.NeedsPasswords)
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Cloud account ready. Sync skipped. Run sshm cloud sync later to add cloud connections to sshm list.")
			return nil
		}}
		c.Flags().BoolVar(&syncLocal, "sync", false, "sync cloud connections into the local list after login")
		c.Flags().BoolVar(&noSync, "no-sync", false, "skip the post-login sync prompt")
		c.MarkFlagsMutuallyExclusive("sync", "no-sync")
		c.Flags().BoolVar(&importLocal, "import-local", false, "after login, encrypt and merge local servers and configured key files, then sync")
		c.MarkFlagsMutuallyExclusive("import-local", "no-sync")
		return c
	}
	root.AddCommand(makeAccount(true), makeAccount(false))
	addCloudLinkCommands(root, &endpoint, &username, &label)
	root.AddCommand(newCloudReportVersionCmd(), newCloudAddDeviceCmd(false), newCloudAddDeviceCmd(true))
	root.AddCommand(&cobra.Command{Use: "status", Short: "Show account and sync status without unlocking", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, release, err := cloudState()
		if err != nil {
			fmt.Fprintln(cmd.OutOrStdout(), "Local mode. Cloud account not configured.")
			return nil
		}
		defer release()
		return writeJSON(cmd.OutOrStdout(), map[string]any{"username": s.Username, "endpoint": s.URL, "device_id": s.DeviceID, "logged_in": s.Token != "", "revision": s.Base.Revision, "unsynced": s.Dirty, "pending_retry": s.Pending != nil, "session_expired": s.Expires < time.Now().UnixMilli()})
	}})
	var withoutKeys bool
	imp := &cobra.Command{Use: "import", Short: "Merge local records and configured key files into the encrypted draft", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer close()
		cfg, err := config.Load(configPath())
		if err != nil {
			return err
		}
		report, err := v.Data.Import(cfg, s.DeviceID, !withoutKeys)
		if err != nil {
			return err
		}
		if err = s.SaveDraft(v, cloudsync.StatePath(configPath())); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Added %d; matched %d; key references %d; keys needing their own passphrase %d; agent-only %d; password entries needing input %d; deleted records skipped %d. Run cloud sync.\n", report.Added, report.Existing, report.Keys, report.LockedKeys, report.AgentOnly, report.NeedsPasswords, report.SkippedDeleted)
		return nil
	}}
	imp.Flags().BoolVar(&withoutKeys, "without-keys", false, "import metadata only")
	root.AddCommand(imp)
	root.AddCommand(newSyncCmd())
	root.AddCommand(&cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "List cloud connection variants from the encrypted offline cache", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer close()
		type row struct {
			ID          string   `json:"id"`
			Aliases     []string `json:"aliases"`
			Host        string   `json:"host"`
			Port        int      `json:"port"`
			User        string   `json:"user"`
			Auth        string   `json:"auth"`
			Device      string   `json:"device_id,omitempty"`
			Credentials int      `json:"credential_count"`
			Conflict    bool     `json:"conflict"`
		}
		rows := []row{}
		for id, e := range v.Data.Entries {
			_, conflict := v.Data.Conflicts[id]
			rows = append(rows, row{id, e.Aliases, e.Server.Host, e.Server.Port, e.Server.User, e.Server.Auth, cloudsync.DeviceServerID(e.Server), len(e.CredentialIDs), conflict})
		}
		sort.Slice(rows, func(i, j int) bool { return strings.Join(rows[i].Aliases, ",") < strings.Join(rows[j].Aliases, ",") })
		if flagJSON {
			return writeJSON(cmd.OutOrStdout(), rows)
		}
		for _, r := range rows {
			if r.Device != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  SSHM client · key-signed, end-to-end encrypted\n", r.ID, safety.MaskSecrets(strings.Join(r.Aliases, ",")))
				continue
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s@%s:%d  %s  (%d credentials)\n", r.ID, safety.MaskSecrets(strings.Join(r.Aliases, ",")), r.User, r.Host, r.Port, r.Auth, r.Credentials)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%d connection variants; %d unresolved conflicts.\n", len(rows), len(v.Data.Conflicts))
		return nil
	}})
	root.AddCommand(&cobra.Command{Use: "save-password <alias-or-id>", Short: "Store an SSH login password inside the encrypted vault", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer close()
		e, err := v.Data.Find(args[0])
		if err != nil {
			return err
		}
		p, err := cloudSecret(cmd, "Server password", true)
		if err != nil {
			return err
		}
		defer cloudsync.Wipe(p)
		if err = v.Data.SetPassword(e.ID, string(p)); err != nil {
			return err
		}
		return s.SaveDraft(v, cloudsync.StatePath(configPath()))
	}})
	root.AddCommand(&cobra.Command{Use: "remove <alias-or-id>", Short: "Delete a cloud connection using a synchronized tombstone", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer close()
		e, err := v.Data.Find(args[0])
		if err != nil {
			return err
		}
		ok, err := confirmExactAlias(cmd, args[0], "remove this cloud connection")
		if err != nil || !ok {
			return err
		}
		v.Data.Remove(e.ID)
		return s.SaveDraft(v, cloudsync.StatePath(configPath()))
	}})
	var resolveID, side string
	conflicts := &cobra.Command{Use: "conflicts", Short: "Review or explicitly resolve concurrent connection edits", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer close()
		if resolveID != "" {
			if err = v.Data.Resolve(resolveID, side); err != nil {
				return err
			}
			return s.SaveDraft(v, cloudsync.StatePath(configPath()))
		}
		ids := []string{}
		for id := range v.Data.Conflicts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			c := v.Data.Conflicts[id]
			fmt.Fprintf(cmd.OutOrStdout(), "%s local=%t remote=%t (false means deletion)\n", id, c.Local != nil, c.Remote != nil)
		}
		return nil
	}}
	conflicts.Flags().StringVar(&resolveID, "resolve", "", "full conflict ID")
	conflicts.Flags().StringVar(&side, "keep", "", "local or remote")
	root.AddCommand(conflicts)
	var revoke string
	devices := &cobra.Command{Use: "devices", Short: "List or revoke devices (previously downloaded secrets cannot be recalled)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, release, err := cloudState()
		if err != nil {
			return err
		}
		defer release()
		if revoke != "" {
			if err = s.Request(cmd.Context(), "DELETE", "/v1/devices/"+revoke, nil, nil); err != nil {
				return err
			}
			if revoke == s.DeviceID {
				s.Token = ""
				return s.Save(cloudsync.StatePath(configPath()))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Device revoked. Use cloud rekey to rotate future vault encryption; rotate any exposed SSH credentials on their servers.")
			return nil
		}
		var out struct {
			Devices []cloudsync.Device `json:"devices"`
		}
		_ = reportClientVersion(cmd.Context())
		if err = s.Request(cmd.Context(), "GET", "/v1/devices", nil, &out); err != nil {
			return err
		}
		return writeJSON(cmd.OutOrStdout(), out)
	}}
	devices.Flags().StringVar(&revoke, "revoke", "", "exact device ID to revoke")
	root.AddCommand(devices)
	root.AddCommand(&cobra.Command{Use: "logout", Short: "Revoke this session and retain the locked encrypted offline cache", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, release, err := cloudState()
		if err != nil {
			return err
		}
		defer release()
		if s.Dirty || s.Pending != nil {
			return errors.New("unsynced changes remain; sync before logging out")
		}
		if s.Token != "" {
			if err = s.Request(cmd.Context(), "DELETE", "/v1/devices/"+s.DeviceID, nil, nil); err != nil {
				var api *cloudsync.APIError
				if !errors.As(err, &api) || api.Status != 401 {
					return err
				}
			}
		}
		s.Token = ""
		s.Expires = 0
		return s.Save(cloudsync.StatePath(configPath()))
	}})
	root.AddCommand(&cobra.Command{Use: "change-password", Short: "Change the account password and revoke other sessions", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, release, err := cloudState()
		if err != nil {
			return err
		}
		defer release()
		old, err := cloudSecret(cmd, "Current account password", false)
		if err != nil {
			return err
		}
		defer cloudsync.Wipe(old)
		p, err := cloudSecret(cmd, "New account password (6+ characters)", true)
		if err != nil {
			return err
		}
		defer cloudsync.Wipe(p)
		if !cloudsync.ValidAccountPassword(p) {
			return errors.New("account password must contain 6-256 characters")
		}
		return s.Request(cmd.Context(), "POST", "/v1/password", map[string]string{"old_password": string(old), "password": string(p)}, nil)
	}})
	root.AddCommand(&cobra.Command{Use: "rekey", Short: "Rotate the vault key, unlock phrase and recovery code; revoke other devices", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer close()
		if s.Dirty || s.Pending != nil {
			return errors.New("sync outstanding changes before rekeying")
		}
		p, err := cloudSecret(cmd, "New vault unlock phrase (6+ characters)", true)
		if err != nil {
			return err
		}
		defer cloudsync.Wipe(p)
		nv, recovery, err := cloudsync.NewVault(s.Username, p)
		if err != nil {
			return err
		}
		defer nv.Close()
		nv.Data = v.Data
		if err = cloudSaveRecovery(cmd, recoveryPath, recovery); err != nil {
			return err
		}
		snap, err := nv.Snapshot(s.Base.Revision, cloudsync.RandomID())
		if err != nil {
			return err
		}
		auth, _ := cloudsync.RecoveryAuth(recovery)
		// Keep the new encrypted snapshot on disk before a potentially ambiguous commit.
		if err = cloudsync.WritePrivate(filepath.Join(filepath.Dir(cloudsync.StatePath(configPath())), "rekey-"+snap.OperationID+".json"), []byte(snap.Blob)); err != nil {
			return err
		}
		var out cloudsync.Snapshot
		in := map[string]any{"base_revision": snap.BaseRevision, "operation_id": snap.OperationID, "blob": snap.Blob, "signature": snap.Signature, "root_public": snap.RootPublic, "recovery_auth": auth, "authorization": v.RotationAuthorization(snap, auth)}
		if err = s.Request(cmd.Context(), "PUT", "/v1/rotate", in, &out); err != nil {
			return err
		}
		if out.Blob != snap.Blob || out.Signature != snap.Signature {
			return errors.New("rotation acknowledgement mismatch")
		}
		s.Base = out
		s.Draft = out
		return s.Save(cloudsync.StatePath(configPath()))
	}})
	root.AddCommand(&cobra.Command{Use: "recover", Short: "Recover account access and vault using an offline recovery code", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		username = strings.ToLower(strings.TrimSpace(username))
		if !cloudsync.ValidAccount(username) {
			return errors.New("provide --username")
		}
		path := cloudsync.StatePath(configPath())
		release, err := cloudsync.Lock(path)
		if err != nil {
			return err
		}
		defer release()
		if s, e := cloudsync.LoadState(path); e == nil && (s.Dirty || s.Token != "") {
			return errors.New("use a fresh --config path to preserve the current cloud state")
		}
		code, err := cloudSecret(cmd, "Recovery code", false)
		if err != nil {
			return err
		}
		defer cloudsync.Wipe(code)
		auth, err := cloudsync.RecoveryAuth(string(code))
		if err != nil {
			return err
		}
		p, err := cloudSecret(cmd, "New account password (6+ characters)", true)
		if err != nil {
			return err
		}
		defer cloudsync.Wipe(p)
		if label == "" {
			// Account credentials are validated locally before transmission.
			label, _ = os.Hostname()
		}
		if !cloudsync.ValidAccountPassword(p) {
			return errors.New("account password must contain 6-256 characters")
		}
		s := &cloudsync.State{URL: endpoint, Username: username, DeviceID: cloudsync.RandomID()}
		var out cloudsync.LoginResult
		if err = s.Request(cmd.Context(), "POST", "/v1/recover", map[string]string{"recovery_auth": auth, "password": string(p), "device_id": s.DeviceID, "label": label}, &out); err != nil {
			return err
		}
		v, err := cloudsync.Unlock(username, out.Snapshot, code, true)
		if err != nil {
			return err
		}
		defer v.Close()
		s.Token = out.Token
		s.Expires = out.Expires
		s.Base = out.Snapshot
		s.Draft = out.Snapshot
		// Recovery proves decryption but does not silently change the existing unlock phrase.
		if err = s.Save(path); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Account and encrypted vault recovered. Original unlock phrase still applies; use cloud rekey --use-recovery to set a new one.")
		return nil
	}})
	root.AddCommand(newCloudConnectionCmd(false), newCloudConnectionCmd(true), newCloudWatchCmd(), newCloudPresenceCmd())
	wrapCloudErrors(root)
	return root
}
func cloudAuth(cmd *cobra.Command, d cloudsync.Data, e cloudsync.Entry, selected string) ([]gssh.Signer, []io.Closer, string, error) {
	var signers []gssh.Signer
	var closers []io.Closer
	var locked []cloudsync.Credential
	password := ""
	matched := selected == ""
	for _, id := range e.CredentialIDs {
		if selected != "" && id != selected {
			continue
		}
		matched = true
		c := d.Credentials[id]
		if c.Kind == "password" {
			if password != "" && password != c.Password {
				return nil, nil, "", fmt.Errorf("multiple saved passwords; choose --credential from: %s", strings.Join(e.CredentialIDs, ", "))
			}
			password = c.Password
			continue
		}
		if c.Kind != "key" {
			continue
		}
		s, err := gssh.ParsePrivateKey(c.Key)
		if err != nil && len(c.Passphrase) > 0 {
			s, err = gssh.ParsePrivateKeyWithPassphrase(c.Key, c.Passphrase)
		}
		if err == nil {
			signers = append(signers, s)
		} else {
			var missing *gssh.PassphraseMissingError
			if errors.As(err, &missing) && missing.PublicKey != nil {
				if agentSigner, closer, agentErr := sshpkg.AgentSignerForPublicKey(missing.PublicKey); agentErr == nil {
					signers = append(signers, agentSigner)
					closers = append(closers, closer)
					continue
				}
			}
			locked = append(locked, c)
		}
	}
	if !matched {
		return nil, nil, "", errors.New("selected credential does not belong to this connection")
	}
	if e.Server.Auth == config.AuthKey && len(signers) == 0 {
		if len(locked) == 0 {
			return nil, nil, "", errors.New("no exported SSH key for this connection")
		}
		p, err := cloudSecret(cmd, "SSH private key passphrase", false)
		if err != nil {
			return nil, nil, "", err
		}
		defer cloudsync.Wipe(p)
		for _, c := range locked {
			if s, err := gssh.ParsePrivateKeyWithPassphrase(c.Key, p); err == nil {
				signers = append(signers, s)
			}
		}
		if len(signers) == 0 {
			return nil, nil, "", errors.New("SSH private key could not be unlocked; Vault has no matching passphrase and the macOS agent has no matching identity")
		}
	}
	if e.Server.Auth == config.AuthPassword && password == "" {
		p, err := cloudSecret(cmd, "Server password (not yet saved)", false)
		if err != nil {
			return nil, nil, "", err
		}
		defer cloudsync.Wipe(p)
		password = string(p)
	}
	return signers, closers, password, nil
}
func newCloudConnectionCmd(run bool) *cobra.Command {
	use := "connect <alias-or-id>"
	args := cobra.ExactArgs(1)
	if run {
		use = "exec <alias-or-id> <command...>"
		args = cobra.MinimumNArgs(2)
	}
	var trust bool
	var credential string
	var seconds int
	c := &cobra.Command{Use: use, Short: "Connect directly using credentials from the encrypted offline vault", Args: args, RunE: func(cmd *cobra.Command, a []string) error {
		state, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		// Connections must not hold the state lock and block agent heartbeat/sync.
		opened, err := cloudsync.UnlockMaster(state.Username, state.Draft, v.Master)
		close()
		if err != nil {
			return err
		}
		v = opened
		defer v.Close()
		e, err := v.Data.Find(a[0])
		if err != nil {
			return err
		}
		if cloudsync.DeviceServerID(e.Server) != "" {
			if run {
				return errors.New("use sshm connect for an encrypted device terminal; non-interactive device exec is not available yet")
			}
			return attachDeviceTerminal(cmd, state, v, e)
		}
		localRoute := false
		for _, src := range e.Sources {
			if src.Device == state.DeviceID {
				localRoute = true
			}
		}
		if !localRoute && !trust && (e.Server.ProxyCommand != "" || e.Server.ProxyJump != "" || e.Server.Proxy != "" || len(e.Server.Forwards) > 0) {
			return errors.New("connection has device-specific proxy/forward settings; review them on the source device and explicitly use --trust-route")
		}
		signers, signerClosers, password, err := cloudAuth(cmd, v.Data, e, credential)
		if err != nil {
			return err
		}
		opts := sshpkg.BuildOpts{Signers: signers, SignerClosers: signerClosers, Password: password, ConfigPath: configPath()}
		opts.ResolveJump = func(alias string) (*config.Server, sshpkg.BuildOpts, error) {
			jump, err := v.Data.Find(strings.TrimSpace(alias))
			if err != nil {
				return nil, sshpkg.BuildOpts{}, fmt.Errorf("cloud jump host: %w; import the jump host into the vault", err)
			}
			if jump.Server.ProxyJump != "" {
				return nil, sshpkg.BuildOpts{}, errors.New("nested cloud jump hosts are not supported")
			}
			if !trust && (jump.Server.ProxyCommand != "" || jump.Server.Proxy != "" || len(jump.Server.Forwards) > 0) {
				return nil, sshpkg.BuildOpts{}, errors.New("review jump host routing and use --trust-route")
			}
			js, jc, jp, err := cloudAuth(cmd, v.Data, jump, "")
			return &jump.Server, sshpkg.BuildOpts{Signers: js, SignerClosers: jc, Password: jp}, err
		}
		client, err := sshpkg.Dial(&e.Server, opts)
		if err != nil {
			return err
		}
		defer client.Close()
		if cfg, loadErr := config.Load(configPath()); loadErr == nil {
			for alias, local := range cfg.Servers {
				if local != nil && local.CloudEntry == e.ID && local.CloudVault == cloudsync.InventoryIdentity(state) {
					if err := config.RecordSSHUse(configPath(), alias, &e.Server, time.Now()); err != nil {
						fmt.Fprintln(cmd.ErrOrStderr(), "SSH connected, but connection time could not be saved.")
					}
				}
			}
		}
		if !run {
			return client.AttachInteractive()
		}
		ctx := cmd.Context()
		if seconds > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
			defer cancel()
		}
		result, err := client.Exec(ctx, strings.Join(a[1:], " "))
		if err != nil {
			return err
		}
		if flagJSON {
			return writeJSON(cmd.OutOrStdout(), result)
		}
		fmt.Fprint(cmd.OutOrStdout(), result.Stdout)
		fmt.Fprint(cmd.ErrOrStderr(), result.Stderr)
		if result.ExitCode != 0 {
			return fmt.Errorf("remote exit code %d", result.ExitCode)
		}
		return nil
	}}
	c.Flags().BoolVar(&trust, "trust-route", false, "explicitly trust the selected proxy/forward settings on this device")
	c.Flags().StringVar(&credential, "credential", "", "use one credential ID when a connection has different saved credentials")
	c.Flags().IntVar(&seconds, "timeout", 60, "remote command timeout in seconds")
	return c
}
func newCloudWatchCmd() *cobra.Command {
	var interval int
	c := &cobra.Command{Use: "watch", Short: "Keep an unlocked vault in this process and sync periodically (Ctrl-C to lock)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if interval < 15 {
			return errors.New("minimum sync interval is 15 seconds")
		}
		state, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		master := append([]byte(nil), v.Master...)
		defer cloudsync.Wipe(master)
		account := state.Username
		close()
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()
		timer := time.NewTicker(time.Duration(interval) * time.Second)
		defer timer.Stop()
		for {
			s, release, e := cloudState()
			if e != nil {
				return e
			}
			if s.Username != account || s.Token == "" {
				release()
				return errors.New("cloud account changed or logged out; watcher locked")
			}
			current, e := cloudsync.UnlockMaster(account, s.Draft, master)
			if e == nil {
				_ = s.Heartbeat(ctx, Version)
				e = s.Sync(ctx, current, cloudsync.StatePath(configPath()))
				current.Close()
			}
			release()
			if e != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), safety.MaskSecrets(friendlyCloudError(e).Error()))
			}
			select {
			case <-ctx.Done():
				return nil
			case <-timer.C:
			}
		}
	}}
	c.Flags().IntVar(&interval, "interval", 30, "seconds between sync checks")
	return c
}

func newCloudPresenceCmd() *cobra.Command {
	var once bool
	c := &cobra.Command{Use: "presence", Short: "Report device status every 30 seconds without unlocking the server vault", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		if !once {
			fmt.Fprintln(cmd.OutOrStdout(), "Device heartbeat active. Ctrl-C stops presence; this does not enable remote shell.")
		}
		var resources *inventory.Snapshot
		for {
			if resources == nil || time.Since(time.UnixMilli(resources.CheckedAt)) >= 5*time.Minute {
				resources = inventory.Collect(ctx)
			}
			s, release, err := cloudState()
			if err != nil {
				return err
			}
			if s.Token == "" {
				release()
				return errors.New("login required for device presence")
			}
			err = s.HeartbeatResources(ctx, Version, resources)
			release()
			if once {
				return err
			}
			if err != nil {
				var api *cloudsync.APIError
				if errors.As(err, &api) && api.Status == 401 {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), safety.MaskSecrets(friendlyCloudError(err).Error()))
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	}}
	c.Flags().BoolVar(&once, "once", false, "report resource metadata once, without vault unlock")
	return c
}

// Read one line only: secret prompts use the terminal directly, never a buffered reader.
func askCloudSync(cmd *cobra.Command) (bool, error) {
	fmt.Fprint(cmd.ErrOrStderr(), "Sync now? [Y/n]: ")
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		fmt.Fprintln(cmd.ErrOrStderr(), "Sync skipped; run sshm cloud sync when ready.")
		return false, nil
	}
}
func publishCloudInventory(cmd *cobra.Command, s *cloudsync.State, v *cloudsync.Vault) error {
	report, err := cloudsync.PublishInventory(configPath(), s, v.Data)
	if err != nil {
		return fmt.Errorf("encrypted sync succeeded, but local list could not be updated: %w; retry sshm cloud sync", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Local list: %d cloud connections, %d existing local matches preserved, %d conflicts withheld. Keys and passwords remain encrypted.\n", report.Cloud, report.Local, report.Conflicts)
	if report.Removed > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Removed %d deleted connections from the local list. SSH key files are retained.\n", report.Removed)
	}
	if report.Backup != "" {
		fmt.Fprintln(cmd.OutOrStdout(), "Recoverable local config backup:", report.Backup)
	}
	if report.Protected > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "%d deleted connections retained because they are defaults, protected, or used by projects/jump hosts; review local dependencies before removing them.\n", report.Protected)
	}
	return nil
}
func runCloudReference(cmd *cobra.Command, server *config.Server, args []string, run bool, timeout int) error {
	s, err := cloudsync.LoadState(cloudsync.StatePath(configPath()))
	if err != nil {
		return errors.New("cloud account unavailable; run sshm cloud login")
	}
	if server.CloudVault != "" && server.CloudVault != cloudsync.InventoryIdentity(s) {
		return errors.New("this connection belongs to another vault; run sshm cloud sync for the current account")
	}
	c := newCloudConnectionCmd(run)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	c.SetContext(ctx)
	c.SetIn(cmd.InOrStdin())
	c.SetOut(cmd.OutOrStdout())
	c.SetErr(cmd.ErrOrStderr())
	_ = c.Flags().Set("timeout", fmt.Sprint(timeout))
	return c.RunE(c, args)
}

func newSyncCmd() *cobra.Command {
	c := &cobra.Command{Use: "sync", Short: "Sync encrypted connections, device entries and deletions", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer close()
		cfg, err := config.Load(configPath())
		if err != nil {
			return err
		}
		if v.Data.ImportActivity(cfg) {
			if err = s.SaveDraft(v, cloudsync.StatePath(configPath())); err != nil {
				return err
			}
		}
		if err = s.Sync(cmd.Context(), v, cloudsync.StatePath(configPath())); err != nil {
			return err
		}
		if err = publishCloudInventory(cmd, s, v); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Synced revision %d. Run sshm list to browse, or sshm connect <alias> to connect.\n", s.Base.Revision)
		return nil
	}}
	c.Flags().Bool("use-recovery", false, "unlock with a recovery code")
	wrapCloudErrors(c)
	return c
}
