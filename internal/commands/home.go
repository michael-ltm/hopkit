package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/michael-ltm/sshm/internal/updater"
	"github.com/spf13/cobra"
)

func textUI(en, zh string) string {
	cfg, _, e := loadConfig()
	if e != nil {
		return en
	}
	return ui.Text(cfg.UI.Language, en, zh)
}
func uiColor(cfg *config.Config) bool {
	return !flagNoColor && cfg.UI.Color != "never" && os.Getenv("NO_COLOR") == ""
}
func homeSummary(cfg *config.Config) ui.HomeSummary {
	out := ui.HomeSummary{}
	state, err := cloudsync.LoadState(cloudsync.StatePath(configPath()))
	identity := ""
	if err == nil {
		identity = cloudsync.InventoryIdentity(state)
		if state.Token != "" && state.Expires > time.Now().UnixMilli() {
			out.Account = state.Username
			out.Pending = state.Dirty
			if summary, ok := cloudsync.ReadInventorySummary(configPath(), state); ok {
				out.CloudKnown = true
				out.Cloud = summary.Count
				out.Synced = time.UnixMilli(summary.Synced).Local().Format("01-02 15:04")
			}
		}
	}
	for _, s := range cfg.Servers {
		if s == nil {
			continue
		}
		out.Total++
		if s.CloudVault != "" && s.CloudVault == identity {
			out.Linked++
		} else if s.Auth == config.AuthCloud || s.CloudVault != "" {
			out.Unlinked++
		} else {
			out.Local++
		}
	}
	return out
}
func homeRelease(ctx context.Context) ui.ReleaseStatus {
	_ = reportClientVersion(ctx)
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	r, _, e := updater.Check(ctx)
	if e != nil {
		return ui.ReleaseStatus{Err: "unavailable"}
	}
	comparison, e := updater.Compare(r.Version, Version)
	if e != nil {
		return ui.ReleaseStatus{Err: "unavailable"}
	}
	return ui.ReleaseStatus{Latest: r.Version, Available: comparison > 0, Verified: true}
}
func newMenuCmd() *cobra.Command {
	return &cobra.Command{Use: "menu", Aliases: []string{"ui"}, Short: "Open the interactive home menu", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if !commandHasTerminal(cmd) {
			return errors.New("menu needs an interactive terminal; use sshm --help or sshm list --json")
		}
		return runHome(cmd)
	}}
}
func runHome(cmd *cobra.Command) error {
	var release ui.ReleaseStatus
	checked := false
	for {
		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}
		summary := homeSummary(cfg)
		model := ui.NewHome(cfg, summary, Version, uiColor(cfg))
		model.Release = release
		ctx, cancel := context.WithCancel(cmd.Context())
		if !checked && os.Getenv("SSHM_NO_UPDATE_CHECK") != "1" {
			model.Check = func() tea.Msg { return homeRelease(ctx) }
		}
		p := tea.NewProgram(model, tea.WithInput(cmd.InOrStdin()), tea.WithOutput(cmd.ErrOrStderr()), tea.WithAltScreen(), tea.WithContext(ctx))
		result, e := p.Run()
		cancel()
		if e != nil {
			return e
		}
		home := result.(ui.Home)
		release = home.Release
		checked = release.Verified || release.Err != ""
		if home.Action == "quit" || home.Action == "" {
			return nil
		}
		var args []string
		switch home.Action {
		case "servers":
			args = []string{"list", "--interactive"}
		case "sync":
			args = []string{"sync"}
		case "devices":
			e = runHomeDevices(cmd)
		case "update":
			args = []string{"update"}
			checked = false
			release = ui.ReleaseStatus{}
		case "settings":
			e = runSettings(cmd)
		case "add":
			choice, err := homeChoice(cmd, textUI("Add connection", "添加连接"), []menuOption{
				{"ssh", textUI("SSH server · address and key pairing", "SSH 服务器 · 地址与密钥配对")},
				{"device", textUI("Add an account device to the vault", "将账号设备加入保险库")},
				{"enable", textUI("Allow connections to this computer", "允许连接本机")},
				{"back", textUI("Back", "返回")},
			})
			e = err
			switch choice {
			case "ssh":
				args = []string{"add"}
			case "enable":
				args = []string{"cloud", "enable"}
			case "device":
				e = runHomeDevices(cmd)
			}
		case "account":
			options := []menuOption{{"login", textUI("Log in", "登录")}, {"register", textUI("Create account", "注册账号")}, {"back", textUI("Back", "返回")}}
			if summary.Account != "" {
				options = []menuOption{{"status", textUI("Account and sync status", "账号与同步状态")}, {"logout", textUI("Log out on this device", "退出本机登录")}, {"back", textUI("Back", "返回")}}
			}
			choice, err := homeChoice(cmd, textUI("Account", "账号"), options)
			e = err
			if choice != "back" && choice != "" {
				args = []string{"cloud", choice}
			}
		case "help":
			choice, err := homeChoice(cmd, textUI("Help", "帮助"), []menuOption{{"commands", textUI("Common commands", "常用命令")}, {"integrations", textUI("Codex / Claude Code integration status", "Codex / Claude Code 集成状态")}, {"back", textUI("Back", "返回")}})
			e = err
			switch choice {
			case "commands":
				fmt.Fprintln(cmd.OutOrStdout(), textUI("sshm                 Home menu\nsshm list            Servers\nsshm connect NAME    Connect\nsshm login / logout  Account\nsshm sync            Sync vault\nsshm devices         Cloud devices\nsshm settings        Language and display\nsshm update          Update or skip\nsshm --help          All commands (existing scripts remain compatible)", "sshm                 主界面\nsshm list            服务器列表\nsshm connect 名称    连接\nsshm login / logout  登录 / 退出登录\nsshm sync            同步保险库\nsshm devices         云端设备\nsshm settings        语言与显示\nsshm update          更新或跳过\nsshm --help          全部命令（保留原有脚本兼容）"))
				e = homePause(cmd)
			case "integrations":
				args = []string{"integrations", "status"}
			}
		}
		if e == nil && len(args) > 0 {
			e = homeRun(cmd, args)
			if e == nil && home.Action == "update" {
				if target, err := updater.Target(); err == nil {
					versionCmd := exec.CommandContext(cmd.Context(), target, "version")
					if out, err := versionCmd.Output(); err == nil && strings.TrimSpace(string(out)) != Version {
						return homeRun(cmd, []string{"menu"})
					}
				}
			}
			if e == nil && home.Action == "servers" {
				continue
			}
			if !errors.Is(e, huh.ErrUserAborted) {
				if e != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), e)
					e = nil
				}
				e = homePause(cmd)
			}
		}
		if e != nil && !errors.Is(e, huh.ErrUserAborted) {
			fmt.Fprintln(cmd.ErrOrStderr(), e)
			_ = homePause(cmd)
		}
	}
}

type menuOption struct{ id, label string }

func homeChoice(cmd *cobra.Command, title string, options []menuOption) (string, error) {
	var choice string
	opts := make([]huh.Option[string], 0, len(options))
	for _, o := range options {
		opts = append(opts, huh.NewOption(o.label, o.id))
	}
	form := huh.NewForm(huh.NewGroup(huh.NewSelect[string]().Title(title).Options(opts...).Value(&choice))).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme()).WithKeyMap(homeKeyMap())
	e := form.Run()
	return choice, e
}
func homePause(cmd *cobra.Command) error {
	_, e := homeChoice(cmd, "SSHM", []menuOption{{"back", textUI("Return to home", "返回主界面")}})
	return e
}
func homeRun(cmd *cobra.Command, args []string) error {
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	argv := []string{"--config", configPath()}
	cfg, _, e := loadConfig()
	if e != nil {
		return e
	}
	if !uiColor(cfg) {
		argv = append(argv, "--no-color")
	}
	argv = append(argv, args...)
	child := exec.CommandContext(cmd.Context(), executable, argv...)
	child.Stdin = cmd.InOrStdin()
	child.Stdout = cmd.OutOrStdout()
	child.Stderr = cmd.ErrOrStderr()
	child.Env = append(os.Environ(), "SSHM_NO_UPDATE_CHECK=1")
	return child.Run()
}
func newSettingsCmd() *cobra.Command {
	var language string
	c := &cobra.Command{Use: "settings", Short: "Set language and terminal appearance", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("language") {
			if language != "auto" && language != "zh-CN" && language != "en" {
				return errors.New("language must be auto, zh-CN or en")
			}
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			cfg.UI.Language = language
			return config.SaveUIPreferences(configPath(), cfg.UI)
		}
		if !commandHasTerminal(cmd) {
			cfg, _, e := loadConfig()
			if e != nil {
				return e
			}
			return writeJSON(cmd.OutOrStdout(), cfg.UI)
		}
		return runSettings(cmd)
	}}
	c.Flags().StringVar(&language, "language", "", "auto, zh-CN or en")
	return c
}
func runSettings(cmd *cobra.Command) error {
	cfg, _, e := loadConfig()
	if e != nil {
		return e
	}
	language, color, icons := cfg.UI.Language, cfg.UI.Color, cfg.UI.Icons
	if language == "" {
		language = "auto"
	}
	if color == "" {
		color = "auto"
	}
	if icons == "" {
		icons = "auto"
	}
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("Language / 语言").Options(huh.NewOption("跟随系统 / System", "auto"), huh.NewOption("简体中文", "zh-CN"), huh.NewOption("English", "en")).Value(&language),
		huh.NewSelect[string]().Title(textUI("Color", "颜色")).Options(huh.NewOption(textUI("Automatic", "自动"), "auto"), huh.NewOption(textUI("No color", "无颜色"), "never")).Value(&color),
		huh.NewSelect[string]().Title(textUI("Symbols", "终端符号")).Options(huh.NewOption(textUI("Automatic", "自动"), "auto"), huh.NewOption("Unicode", "unicode"), huh.NewOption("ASCII", "ascii")).Value(&icons),
	)).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme()).WithKeyMap(homeKeyMap())
	if e = form.Run(); e != nil {
		return e
	}
	return config.SaveUIPreferences(configPath(), config.UIConfig{Language: language, Color: color, Icons: icons})
}

func homeKeyMap() *huh.KeyMap {
	k := huh.NewDefaultKeyMap()
	k.Quit.SetKeys("esc", "ctrl+c")
	return k
}
func runHomeDevices(cmd *cobra.Command) error {
	s, release, e := cloudState()
	if e != nil {
		return e
	}
	release()
	var out struct {
		Devices []cloudsync.Device `json:"devices"`
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 8*time.Second)
	defer cancel()
	if e = s.Request(ctx, "GET", "/v1/devices", nil, &out); e != nil {
		return e
	}
	agents, agentErr := s.Agents(ctx)
	available := map[string]cloudsync.AgentCapability{}
	for _, a := range agents {
		available[a.DeviceID] = a
	}
	options := []menuOption{}
	for _, d := range out.Devices {
		if d.Kind == "browser" {
			continue
		}
		status := textUI("offline", "离线")
		if d.LastSeen > 0 && time.Now().UnixMilli()-d.LastSeen < 90_000 {
			status = textUI("online", "在线")
		}
		if a, ok := available[d.ID]; ok {
			status = textUI("connections enabled", "可连接")
			if !a.Continuous {
				status = textUI("update agent required", "需升级代理")
			}
		}
		if agentErr != nil {
			status += textUI(" / agent unknown", " / 代理未知")
		}
		options = append(options, menuOption{d.ID, ui.SanitizeTerminalText(d.Label) + "  ·  " + ui.SanitizeTerminalText(d.Platform) + "  ·  " + status})
	}
	options = append(options, menuOption{"back", textUI("Back", "返回")})
	choice, e := homeChoice(cmd, textUI("Cloud devices · select to add to vault", "云端设备 · 选择后加入保险库"), options)
	if e != nil || choice == "back" {
		return e
	}
	e = homeRun(cmd, []string{"cloud", "add-device", choice})
	if e != nil {
		return e
	}
	return homePause(cmd)
}
