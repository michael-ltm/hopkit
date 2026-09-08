package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/michael-ltm/sshm/internal/cloudagent"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"strings"
	"time"
)

func addCloudLinkCommands(root *cobra.Command, endpoint, username, label *string) {
	var pinned, progress string
	var importLocal, harden, serve, allowShell bool
	link := &cobra.Command{Use: "link", Short: "Request approval from your unlocked browser without typing account secrets", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		path := cloudsync.StatePath(configPath())
		unlock, e := cloudsync.Lock(path)
		if e != nil {
			return e
		}
		locked := true
		defer func() {
			if locked {
				unlock()
			}
		}()
		old, e := cloudsync.LoadState(path)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		user := strings.ToLower(strings.TrimSpace(*username))
		if user == "" && old != nil {
			user = old.Username
		}
		if !cloudsync.ValidAccount(user) {
			return errors.New("provide --username")
		}
		device := ""
		if old != nil {
			if old.Username != user || old.URL != *endpoint {
				return errors.New("existing cloud identity differs; use another --config")
			}
			if old.Dirty || old.Pending != nil {
				return errors.New("sync existing encrypted changes before linking again")
			}
			device = old.DeviceID
			if pinned == "" {
				pinned = old.Base.RootPublic
			}
		}
		if *label == "" {
			*label, _ = os.Hostname()
		}
		r, e := cloudsync.NewLinkRequest(device, *label, pinned, allowShell)
		if e != nil {
			return e
		}
		s := &cloudsync.State{URL: *endpoint, Username: user}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()
		approvalCtx, stop := context.WithTimeout(ctx, 10*time.Minute)
		defer stop()
		if e = s.BeginLink(approvalCtx, r); e != nil {
			return e
		}
		update := func(state string, extra any) error {
			if progress == "" {
				return nil
			}
			b, e := json.Marshal(map[string]any{"status": state, "request_id": r.ID, "device_id": r.DeviceID, "label": r.Label, "code": cloudsync.LinkCode(r.PublicKey), "details": extra})
			if e != nil {
				return e
			}
			return cloudsync.WritePrivate(progress, b)
		}
		if e = update("awaiting_approval", nil); e != nil {
			return e
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Approve %s in %s/devices. Verify code %s. Expires in 10 minutes.\n", r.Label, s.URL, cloudsync.LinkCode(r.PublicKey))
		v, e := s.WaitLink(approvalCtx, r)
		if e != nil {
			_ = update("approval_failed", nil)
			return e
		}
		defer v.Close()
		if old != nil && s.Base.Revision < old.Base.Revision {
			return errors.New("cloud history rollback detected")
		}
		if e = s.Save(path); e != nil {
			return e
		}
		_ = s.Request(ctx, "DELETE", "/v1/link/"+r.ID, nil, nil)
		cfg, e := config.Load(configPath())
		if e != nil {
			return e
		}
		if importLocal {
			report, e := v.Data.Import(cfg, s.DeviceID, true)
			if e != nil {
				return e
			}
			if e = s.SaveDraft(v, path); e != nil {
				return e
			}
			if e = s.SyncRetry(ctx, v, path); e != nil {
				return e
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Merged revision %d: %d new, %d matched, %d keys, %d locked keys, %d passwords still needed. Local configuration preserved.\n", s.Base.Revision, report.Added, report.Existing, report.Keys, report.LockedKeys, report.NeedsPasswords)
		}
		if e = publishCloudInventory(cmd, s, v); e != nil {
			return e
		}
		if harden {
			report, e := s.HardenLocal(ctx, v, cfg, path)
			if e != nil {
				_ = update("hardening_failed", report)
				return e
			}
			if e = update("keys_protected", report); e != nil {
				return e
			}
			if e = writeJSON(cmd.OutOrStdout(), report); e != nil {
				return e
			}
		}
		_ = s.Heartbeat(ctx, Version)
		unlock()
		locked = false
		if e = update("ready", map[string]any{"revision": s.Base.Revision, "entries": len(v.Data.Entries), "conflicts": len(v.Data.Conflicts), "shell_enabled": serve && allowShell}); e != nil {
			return e
		}
		if serve {
			return runCloudAgent(ctx, cmd, s, v, allowShell)
		}
		return nil
	}}
	link.Flags().StringVar(&pinned, "root-public", "", "verified vault public key from your unlocked browser")
	link.Flags().StringVar(&progress, "progress-file", "", "private progress JSON containing status and pairing code only")
	link.Flags().BoolVar(&importLocal, "import-local", false, "merge configured local records and key files after approval")
	link.Flags().BoolVar(&harden, "harden-keys", false, "back up keys in the encrypted vault, protect local files and load the SSH agent")
	link.Flags().BoolVar(&serve, "serve", false, "keep encrypted sync and presence running after approval")
	link.Flags().BoolVar(&allowShell, "allow-shell", false, "allow encrypted web terminals as this OS user while serving")
	root.AddCommand(link)
	var agentShell bool
	agent := &cobra.Command{Use: "agent", Short: "Run encrypted sync and optionally allow web terminals after local unlock", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, v, close, e := cloudOpen(cmd)
		if e != nil {
			return e
		}
		// cloudOpen owns the file lock; copy the master into an independent vault and
		// release the lock before the long-lived loop.
		agentVault, e := cloudsync.UnlockMaster(s.Username, s.Draft, v.Master)
		close()
		if e != nil {
			return e
		}
		defer agentVault.Close()
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()
		return runCloudAgent(ctx, cmd, s, agentVault, agentShell)
	}}
	agent.Flags().BoolVar(&agentShell, "allow-shell", false, "explicitly allow web terminals as this OS user")
	root.AddCommand(agent)
}
func runCloudAgent(ctx context.Context, cmd *cobra.Command, state *cloudsync.State, v *cloudsync.Vault, allowShell bool) error {
	ctx, cancel := context.WithCancel(ctx)
	errorsCh := make(chan error, 1)
	serveDone := false
	defer func() {
		cancel()
		if allowShell && !serveDone {
			<-errorsCh
		}
	}()
	fmt.Fprintf(cmd.OutOrStdout(), "Cloud agent running; web shell enabled: %t. Master stays in process memory; restart requires unlock or browser approval.\n", allowShell)
	if allowShell {
		state.RuntimeVersion = Version
		go func() { errorsCh <- cloudagent.ServeTargets(ctx, state, v, configPath()) }()
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var hardware *inventory.Snapshot
	for {
		if hardware == nil || time.Since(time.UnixMilli(hardware.CheckedAt)) >= 5*time.Minute {
			hardware = inventory.Collect(ctx)
		}
		path := cloudsync.StatePath(configPath())
		release, e := cloudsync.Lock(path)
		if e == nil {
			s, err := cloudsync.LoadState(path)
			if err == nil && (s.Token != state.Token || s.DeviceID != state.DeviceID || s.Username != state.Username) {
				err = errors.New("agent session changed; restart after unlocking")
			}
			if err == nil {
				err = s.HeartbeatResources(ctx, Version, hardware)
			}
			if err == nil {
				var opened *cloudsync.Vault
				opened, err = cloudsync.UnlockMaster(s.Username, s.Draft, v.Master)
				if err == nil {
					err = s.Sync(ctx, opened, path)
					if err == nil {
						changed := opened.Data.RepairCompatibleConflicts() > 0
						if opened.Data.Hardware == nil {
							opened.Data.Hardware = map[string]*inventory.Snapshot{}
						}
						if old := opened.Data.Hardware[s.DeviceID]; inventory.Newer(old, hardware) != old {
							opened.Data.Hardware[s.DeviceID] = inventory.Newer(old, hardware)
							changed = true
						}
						if cfg, loadErr := config.Load(configPath()); loadErr == nil {
							changed = opened.Data.ImportActivity(cfg) || changed
						}
						if changed {
							err = s.SaveDraft(opened, path)
							if err == nil {
								err = s.SyncRetry(ctx, opened, path)
							}
						}
					}
					if err == nil {
						err = s.ProcessJobs(ctx, opened, path, func(jobCtx context.Context, job cloudsync.Job) cloudsync.JobResult {
							return executeCloudJob(jobCtx, s, opened, path, job)
						})
					}
					opened.Close()
				}
			}
			release()
			e = err
		}
		if e != nil {
			var api *cloudsync.APIError
			if errors.As(e, &api) && (api.Status == 401 || api.Status == 403) {
				return e
			}
			if e.Error() == "agent session changed; restart after unlocking" {
				return e
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Sync not completed; encrypted local data retained.")
		}
		select {
		case <-ctx.Done():
			return nil
		case e := <-errorsCh:
			serveDone = true
			return e
		case <-ticker.C:
		}
	}
}
