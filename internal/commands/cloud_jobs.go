package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/updater"
	"github.com/spf13/cobra"
	"io"
	"time"
)

func executeCloudJob(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault, path string, j cloudsync.Job) cloudsync.JobResult {
	fail := cloudsync.JobResult{Status: "failed", Code: "operation_failed"}
	// Presence remains accurate during bounded scans/downloads.
	presence := *s
	heartbeatCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-t.C:
				_ = presence.Heartbeat(heartbeatCtx, Version)
			}
		}
	}()
	if j.Action == "update" {
		release, _, e := updater.Check(ctx)
		if e != nil {
			fail.Code = "update_check_failed"
			return fail
		}
		if release.Version != j.Version {
			fail.Code = "release_changed"
			return fail
		}
		installed, e := cloudsync.InstalledVersion(ctx)
		if e != nil {
			fail.Code = "installed_version_unknown"
			return fail
		}
		n, e := updater.Compare(release.Version, installed)
		if e != nil {
			return fail
		}
		if n <= 0 {
			if installed != Version {
				return cloudsync.JobResult{Status: "restart_required", Code: "installed_restart_required"}
			}
			return cloudsync.JobResult{Status: "succeeded", Code: "up_to_date"}
		}
		cmd := &cobra.Command{}
		cmd.SetContext(ctx)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if _, e = installRelease(cmd, release); e != nil {
			fail.Code = "update_install_failed"
			return fail
		}
		return cloudsync.JobResult{Status: "restart_required", Code: "installed_restart_required"}
	}
	count := 0
	if j.Action == "inspect" {
		var output bytes.Buffer
		cmd := newInspectCmd()
		cmd.SetContext(ctx)
		cmd.SetOut(&output)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"--all", "--timeout", "15"})
		if e := cmd.Execute(); e != nil {
			fail.Code = "inspection_failed"
			return fail
		}
		var rows []struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(output.Bytes(), &rows) != nil {
			return fail
		}
		for _, r := range rows {
			if r.Status == "detected" {
				count++
			}
		}
	}
	fail.Code = "local_config_unavailable"
	cfg, e := config.Load(configPath())
	if e != nil {
		return fail
	}
	fail.Code = "sync_failed"
	if j.Action == "sync" {
		if _, e = v.Data.Import(cfg, s.DeviceID, true); e != nil {
			return fail
		}
		count = len(v.Data.Entries)
	}
	v.Data.ImportActivity(cfg)
	if e = s.SaveDraft(v, path); e != nil {
		return fail
	}
	if e = s.SyncRetry(ctx, v, path); e != nil {
		return fail
	}
	code := "synced"
	if j.Action == "inspect" {
		code = "inspected"
	}
	return cloudsync.JobResult{Status: "succeeded", Code: code, Count: count}
}
