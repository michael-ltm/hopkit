package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/michael-ltm/sshm/internal/updater"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func newUpdateCmd() *cobra.Command {
	var check, yes bool
	c := &cobra.Command{Use: "update", Short: "Check signed releases and optionally update the standalone client", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		release, _, err := updater.Check(cmd.Context())
		if err != nil {
			return err
		}
		comparison, err := updater.Compare(release.Version, Version)
		if err != nil {
			return err
		}
		if flagJSON {
			return writeJSON(cmd.OutOrStdout(), map[string]any{"current": Version, "latest": release.Version, "update_available": comparison > 0})
		}
		if comparison <= 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "Already up to date:", Version)
			return nil
		}
		asset, err := release.Asset()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Update available: %s → %s (%d bytes, signed release).\n", Version, release.Version, asset.Size)
		if check {
			return nil
		}
		if !yes {
			approved, err := confirmUpdate(cmd, release.Version)
			if err != nil {
				return err
			}
			if !approved {
				fmt.Fprintln(cmd.OutOrStdout(), "Update skipped.")
				return nil
			}
		}
		_, err = installRelease(cmd, release)
		return err
	}}
	c.Flags().BoolVar(&check, "check", false, "only check; do not change files")
	c.Flags().BoolVar(&yes, "yes", false, "explicitly approve this update without an interactive confirmation")
	return c
}

func installRelease(cmd *cobra.Command, release *updater.Release) (string, error) {
	asset, err := release.Asset()
	if err != nil {
		return "", err
	}

	target, err := updater.Target()
	if err != nil {
		return "", err
	}
	releaseLock, err := cloudsync.Lock(target + ".update")
	if err != nil {
		return "", err
	}
	defer releaseLock()
	staged, err := updater.Download(cmd.Context(), asset, filepath.Dir(target))
	if err != nil {
		return "", err
	}
	defer os.Remove(staged)
	backup, err := updater.Replace(target, staged)
	if err != nil {
		return "", err
	}
	_ = reportClientVersion(cmd.Context())
	fmt.Fprintf(cmd.OutOrStdout(), "Updated to %s. Rollback binary: %s\n", release.Version, backup)
	refresh := exec.CommandContext(cmd.Context(), target, "integrations", "refresh")
	refresh.Stdout = cmd.OutOrStdout()
	refresh.Stderr = cmd.ErrOrStderr()
	if err = refresh.Run(); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Client updated; one or more integrations were retained. Run sshm integrations status.")
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Already-running MCP hosts and cloud agents keep their loaded version; restart them to activate this update.")
	return target, nil
}

type updateCache struct {
	Checked int64           `json:"checked"`
	Signed  json.RawMessage `json:"signed,omitempty"`
}

func updateHint(cmd *cobra.Command) {
	if cmd.Name() == "sshm" || cmd.Name() == "menu" {
		return
	}
	if flagJSON || !commandHasTerminal(cmd) || os.Getenv("SSHM_NO_UPDATE_CHECK") == "1" {
		return
	}
	for p := cmd; p != nil; p = p.Parent() {
		switch p.Name() {
		case "mcp", "cloud", "update", "integrations", "completion", "version":
			return
		}
	}
	path := configPath() + ".updates.json"
	var cache updateCache
	if b, e := os.ReadFile(path); e == nil {
		_ = json.Unmarshal(b, &cache)
	}
	if time.Now().Unix()-cache.Checked > 6*3600 {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		r, b, e := updater.Check(ctx)
		cancel()
		// Successful checks are cached for six hours. Retry a failed network
		// check after ten minutes, retaining any still-valid signed notice.
		cache.Checked = time.Now().Unix() - 6*3600 + 10*60
		if e == nil && r != nil {
			cache.Checked = time.Now().Unix()
			cache.Signed = b
		}
		encoded, _ := json.Marshal(cache)
		_ = cloudsync.WritePrivate(path, encoded)
	}
	if len(cache.Signed) > 0 {
		if r, e := updater.Verify(cache.Signed, updater.PublicKey, time.Now()); e == nil {
			if n, e := updater.Compare(r.Version, Version); e == nil && n > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "SSHM %s is available (current %s). Run sshm update to review and install.\n", r.Version, Version)
			}
		}
	}
}

func confirmUpdate(cmd *cobra.Command, latest string) (bool, error) {
	if !commandHasTerminal(cmd) {
		return false, fmt.Errorf("run interactively to confirm, or explicitly pass --yes")
	}
	choice := "skip"
	form := huh.NewForm(huh.NewGroup(huh.NewSelect[string]().
		Title(textUI("SSHM update available", "SSHM 发现新版本")).
		Description(fmt.Sprintf("%s → %s · signed release", Version, latest)).
		Options(huh.NewOption(textUI("Update now", "立即更新"), "update"), huh.NewOption(textUI("Skip for now", "暂时跳过"), "skip")).Value(&choice),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme())
	if err := form.Run(); err != nil {
		return false, err
	}
	return choice == "update", nil
}

// Startup choices are limited to the interactive inventory. MCP, JSON, pipes
// and one-off SSH commands never wait for an update menu.
func offerStartupUpdate(cmd *cobra.Command) (bool, error) {
	if flagJSON || !commandHasTerminal(cmd) || os.Getenv("SSHM_NO_UPDATE_CHECK") == "1" {
		return false, nil
	}
	var cache updateCache
	data, err := os.ReadFile(configPath() + ".updates.json")
	if err != nil || json.Unmarshal(data, &cache) != nil {
		return false, nil
	}
	release, err := updater.Verify(cache.Signed, updater.PublicKey, time.Now())
	if err != nil {
		return false, nil
	}
	newer, err := updater.Compare(release.Version, Version)
	if err != nil || newer <= 0 {
		return false, nil
	}
	approved, err := confirmUpdate(cmd, release.Version)
	if err != nil {
		return true, err
	}
	if !approved {
		return false, nil
	}
	target, err := installRelease(cmd, release)
	if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Update could not finish:", err)
		fmt.Fprintln(cmd.ErrOrStderr(), "Continuing with the running version; retry with sshm update.")
		return false, nil
	}
	// Relaunch the updated inventory as a child on every OS, including Windows
	// where the old executable may remain mapped until this parent exits.
	args := []string{"--config", configPath(), "list", "--interactive"}
	if flagNoColor {
		args = append(args, "--no-color")
	}
	child := exec.CommandContext(cmd.Context(), target, args...)
	child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
	child.Env = append(os.Environ(), "SSHM_NO_UPDATE_CHECK=1")
	return true, child.Run()
}
