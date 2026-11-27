package commands

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/hopkit/internal/cloudsync"
	"github.com/michael-ltm/hopkit/internal/config"
	"github.com/michael-ltm/hopkit/internal/ui"
	"github.com/spf13/cobra"
)

// runCloudSync uploads chosen local-only servers, then syncs. With only set,
// those aliases are uploaded without asking; otherwise a terminal user picks
// from the local servers the cloud does not have yet.
func runCloudSync(cmd *cobra.Command, only []string) error {
	s, v, close, err := cloudOpen(cmd)
	if err != nil {
		return err
	}
	defer close()
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	uploaded, err := uploadLocalServers(cmd, s, v, cfg, only)
	if err != nil {
		return err
	}
	if v.Data.ImportActivity(cfg) || uploaded {
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
	fmt.Fprintf(cmd.OutOrStdout(), "Synced revision %d. Run hopkit list to browse, or hopkit connect <alias> to connect.\n", s.Base.Revision)
	return nil
}

// uploadLocalServers imports the selected local-only servers into the vault
// draft and reports whether anything changed. Unselected servers are
// remembered as local-only so later syncs stop asking about them.
func uploadLocalServers(cmd *cobra.Command, s *cloudsync.State, v *cloudsync.Vault, cfg *config.Config, only []string) (bool, error) {
	candidates := v.Data.ImportCandidates(cfg, cloudsync.InventoryIdentity(s))
	var selected []string
	if only != nil {
		for _, alias := range candidates {
			if slices.Contains(only, alias) {
				selected = append(selected, alias)
			}
		}
	} else {
		offered := []string{}
		for _, alias := range candidates {
			if !slices.Contains(s.LocalOnly, alias) {
				offered = append(offered, alias)
			}
		}
		if len(offered) == 0 {
			return false, nil
		}
		if flagJSON || !commandHasTerminal(cmd) {
			fmt.Fprintf(cmd.ErrOrStderr(), "%d local servers are not in the cloud yet (%s); run hopkit cloud import --only <alias> to upload.\n", len(offered), strings.Join(offered, ", "))
			return false, nil
		}
		picked, err := pickServersToUpload(cmd, cfg, offered)
		if err != nil {
			return false, err
		}
		selected = picked
		for _, alias := range offered {
			if !slices.Contains(picked, alias) {
				s.LocalOnly = append(s.LocalOnly, alias)
			}
		}
		if err = s.Save(cloudsync.StatePath(configPath())); err != nil {
			return false, err
		}
		if len(picked) < len(offered) {
			fmt.Fprintln(cmd.ErrOrStderr(), textUI("Unselected servers stay local and will not be offered again; upload later with hopkit cloud import --only <alias>.", "未勾选的服务器保留在本机，之后不再询问；需要时运行 hopkit cloud import --only <别名> 上传。"))
		}
	}
	if len(selected) == 0 {
		return false, nil
	}
	report, err := v.Data.ImportProtected(cmd.Context(), onlyServers(cfg, selected), s.DeviceID, true, localCredentialStore(configPath()), cloudsync.InventoryIdentity(s))
	if err != nil {
		return false, err
	}
	s.LocalOnly = slices.DeleteFunc(s.LocalOnly, func(alias string) bool { return slices.Contains(selected, alias) })
	fmt.Fprintf(cmd.OutOrStdout(), textUI("Uploading %d servers to the cloud: %s\n", "上传 %d 台服务器到云端：%s\n"), report.Added, strings.Join(selected, ", "))
	return true, nil
}

func pickServersToUpload(cmd *cobra.Command, cfg *config.Config, aliases []string) ([]string, error) {
	options := make([]huh.Option[string], 0, len(aliases))
	for _, alias := range aliases {
		p := cfg.Servers[alias]
		label := ui.SanitizeTerminalText(fmt.Sprintf("%s  ·  %s@%s", alias, p.User, p.Host))
		options = append(options, huh.NewOption(label, alias).Selected(true))
	}
	selected := []string{}
	form := huh.NewForm(huh.NewGroup(
		huh.NewMultiSelect[string]().
			Title(textUI(fmt.Sprintf("%d local servers are not in the cloud", len(aliases)), fmt.Sprintf("本机有 %d 台服务器还没上传到云端", len(aliases)))).
			Description(textUI("Selected servers and their keys are uploaded end-to-end encrypted so your other devices get them. Space toggles, Enter confirms.", "勾选的服务器及密钥会端到端加密上传，其他设备同步后即可使用。空格切换，回车确认。")).
			Options(options...).Value(&selected),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme()).WithKeyMap(homeKeyMap())
	if err := form.Run(); err != nil {
		return nil, err
	}
	return selected, nil
}

func onlyServers(cfg *config.Config, aliases []string) *config.Config {
	out := config.New()
	for _, alias := range aliases {
		if p := cfg.Servers[alias]; p != nil {
			out.Servers[alias] = p
		}
	}
	return out
}

// offerCloudUploadAfterAdd asks a logged-in terminal user whether a newly
// added server should be uploaded and synced to their other devices.
func offerCloudUploadAfterAdd(cmd *cobra.Command, alias string) error {
	s, err := cloudsync.LoadState(cloudsync.StatePath(configPath()))
	if err != nil || s.Token == "" || s.Expires <= time.Now().UnixMilli() || !commandHasTerminal(cmd) {
		return nil
	}
	upload := true
	form := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(textUI(fmt.Sprintf("Upload %q to the cloud?", alias), fmt.Sprintf("上传 %q 到云端？", alias))).
			Description(textUI("Your other devices get it on their next sync. The key is end-to-end encrypted.", "其他设备下次同步即可使用，密钥端到端加密。")).
			Affirmative(textUI("Upload and sync", "上传并同步")).Negative(textUI("Keep local", "仅保留本机")).Value(&upload),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme()).WithKeyMap(homeKeyMap())
	if err := form.Run(); err != nil || !upload {
		return nil
	}
	if err := runCloudSync(cmd, []string{alias}); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), textUI("Server saved locally, but upload failed:", "服务器已保存在本机，但上传失败："), err)
		fmt.Fprintln(cmd.ErrOrStderr(), textUI("Retry with hopkit sync.", "稍后运行 hopkit sync 重试。"))
	}
	return nil
}
