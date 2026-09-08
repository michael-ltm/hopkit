package ui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/michael-ltm/sshm/internal/config"
	"strings"
)

type ReleaseStatus struct {
	Latest              string
	Available, Verified bool
	Err                 string
}
type HomeSummary struct {
	Account                               string
	Total, Local, Linked, Cloud, Unlinked int
	CloudKnown                            bool
	Synced                                string
	Pending                               bool
}
type Home struct {
	Config                *config.Config
	Summary               HomeSummary
	Version, Action       string
	Release               ReleaseStatus
	Check                 tea.Cmd
	width, height, cursor int
	color                 bool
}
type homeItem struct{ id, title, detail string }

func NewHome(cfg *config.Config, summary HomeSummary, version string, color bool) Home {
	return Home{Config: cfg, Summary: summary, Version: version, width: 100, height: 28, color: color}
}
func (m Home) tr(en, zh string) string { return Text(m.Config.UI.Language, en, zh) }
func (m Home) items() []homeItem {
	account, accountHelp := m.tr("Log in", "登录账号"), m.tr("Optional cloud account; local servers work without login", "可选云账号；不登录也能使用本地服务器")
	if m.Summary.Account != "" {
		account = m.tr("Account / log out", "账号 / 退出登录")
		accountHelp = m.tr("Account status, log out or manage devices", "查看账号状态、退出登录和管理设备")
	}
	return []homeItem{
		{"servers", m.tr("Servers", "服务器列表"), m.tr("Recent connections first · search, connect and manage", "最近使用优先 · 搜索、连接和管理")},
		{"add", m.tr("Add server / device", "添加服务器 / 设备"), m.tr("SSH server, cloud device or enable this computer", "添加 SSH 服务器、云端设备，或允许连接本机")},
		{"sync", m.tr("Sync", "同步保险库"), m.tr("Sync encrypted connections and deletions", "同步加密连接和删除记录")},
		{"devices", m.tr("Cloud devices", "云端设备"), m.tr("View account devices and connection availability", "查看账号下的设备与连接状态")},
		{"account", account, accountHelp},
		{"update", m.tr("Check for updates", "检查更新"), m.tr("Verify signed releases · choose update or skip", "验证签名版本 · 自行选择更新或跳过")},
		{"settings", m.tr("Settings", "设置"), m.tr("Language, color and terminal symbols", "语言、颜色和终端符号")},
		{"help", m.tr("Help / AI integrations", "帮助 / AI 集成"), m.tr("Common commands and Codex / Claude Code integration status", "常用命令与 Codex / Claude Code 集成状态")},
		{"quit", m.tr("Quit", "退出"), m.tr("Close this menu; keep your account signed in", "关闭菜单，保留账号登录状态")},
	}
}
func (m Home) Init() tea.Cmd { return m.Check }
func (m Home) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case ReleaseStatus:
		m.Release = v
	case tea.WindowSizeMsg:
		m.width = max(1, v.Width)
		m.height = max(1, v.Height)
	case tea.KeyMsg:
		key := v.String()
		switch key {
		case "ctrl+c", "q", "esc":
			m.Action = "quit"
			return m, tea.Quit
		case "up", "k":
			m.cursor = (m.cursor + len(m.items()) - 1) % len(m.items())
		case "down", "j", "tab":
			m.cursor = (m.cursor + 1) % len(m.items())
		case "enter":
			m.Action = m.items()[m.cursor].id
			return m, tea.Quit
		case "s":
			m.Action = "servers"
			return m, tea.Quit
		case "a":
			m.Action = "add"
			return m, tea.Quit
		case "y":
			m.Action = "sync"
			return m, tea.Quit
		case "l":
			m.Action = "account"
			return m, tea.Quit
		case "u":
			m.Action = "update"
			return m, tea.Quit
		case ",":
			m.Action = "settings"
			return m, tea.Quit
		case "?":
			m.Action = "help"
			return m, tea.Quit
		}
	}
	return m, nil
}
func (m Home) View() string {
	b := Browser{width: m.width, height: m.height, color: m.color, ascii: ResolveIcons(m.Config.UI.Icons).Online == "[OK]"}
	if m.width < 30 || m.height < 15 {
		return b.fit([]string{"SSHM", m.tr("Resize terminal to 30 x 15", "请放大终端至 30 × 15"), "q · " + m.tr("quit", "退出")})
	}
	w := max(1, m.width-4)
	status := m.tr("Checking update…", "正在检查更新…")
	if m.Check == nil {
		status = m.tr("Not checked", "未检查更新")
	}
	if m.Release.Err != "" {
		status = m.tr("Update check unavailable", "暂时无法检查更新")
	}
	if m.Release.Verified {
		status = m.tr("Up to date", "已是最新版本")
		if m.Release.Available {
			status = m.tr("Update available: ", "发现新版本：") + SanitizeTerminalText(m.Release.Latest)
		}
	}
	account := m.tr("Local mode · not logged in", "本地模式 · 未登录")
	if m.Summary.Account != "" {
		account = m.tr("Account: ", "账号：") + SanitizeTerminalText(m.Summary.Account) + m.tr("  ·  Vault locked", "  ·  保险库已锁定")
	}
	cloud := "—"
	if m.Summary.CloudKnown {
		cloud = fmt.Sprint(m.Summary.Cloud)
	}
	counts := fmt.Sprintf(m.tr("%d in local list  ·  %d local-only  ·  %d cloud-linked", "本机列表 %d  ·  仅本地 %d  ·  云端关联 %d"), m.Summary.Total, m.Summary.Local, m.Summary.Linked)
	if m.Summary.Unlinked > 0 {
		counts += fmt.Sprintf(m.tr("  ·  %d need sync", "  ·  待同步关联 %d"), m.Summary.Unlinked)
	}
	sync := m.tr("Cloud snapshot: ", "云端快照：") + cloud
	if m.Summary.Synced != "" {
		sync += m.tr("  ·  last sync ", "  ·  上次同步 ") + m.Summary.Synced
	} else {
		sync += m.tr("  ·  sync to refresh", "  ·  同步后刷新")
	}
	if m.Summary.Pending {
		sync += m.tr("  ·  unpublished changes", "  ·  有待同步更改")
	}
	lines := []string{b.paint("SSHM", "brand") + b.paint("   v"+SanitizeTerminalText(m.Version), "muted"), b.paint(status, "muted"), "", account, b.paint(counts, "muted")}
	if m.Summary.Account != "" {
		lines = append(lines, b.paint(sync, "muted"))
	}
	lines = append(lines, "", b.paint(strings.Repeat("─", w), "rule"))
	items := m.items()
	capacity := max(1, min(len(items), m.height-len(lines)-5))
	offset := max(0, min(m.cursor-capacity+1, len(items)-capacity))
	for i := offset; i < min(len(items), offset+capacity); i++ {
		line := "  " + items[i].title
		if i == m.cursor {
			line = b.paint(PadRightWidth("› "+items[i].title, w), "selected")
		}
		lines = append(lines, line)
	}
	lines = append(lines, b.paint(strings.Repeat("─", w), "rule"), b.paint(items[m.cursor].detail, "muted"), "", b.paint(m.tr("↑↓ move   Enter select   s servers   y sync   , settings   q quit", "↑↓ 选择   Enter 打开   s 列表   y 同步   , 设置   q 退出"), "muted"))
	return b.fit(lines)
}
