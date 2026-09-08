package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/michael-ltm/sshm/internal/config"
)

// Browser is a local inventory view. Only an explicit probe key delegates TCP
// checks to the caller; browsing does not expose credentials or key paths. Descriptions
// retain the existing local UI's legacy Notes fallback.
type Browser struct {
	Config                        *config.Config
	Version, Account              string
	Choice, Action                string
	width, height, cursor, offset int
	query                         textinput.Model
	groups, visible               []string
	group                         int
	recent, help, color           bool
	ascii                         bool
	Probe                         func(string) tea.Cmd
	latencies                     map[string]LatencyResult
	probeQueue                    []string
	probing                       int
	pending                       map[string]bool
}

type LatencyResult struct {
	Alias           string
	Duration        time.Duration
	Failed, Skipped bool
}
type browserTick time.Time

func tickBrowser() tea.Cmd {
	return tea.Tick(15*time.Second, func(t time.Time) tea.Msg { return browserTick(t) })
}

func NewBrowser(cfg *config.Config, initial, version, account string, color bool) Browser {
	if initial == "" {
		initial = cfg.Default
	}
	input := textinput.New()
	input.Prompt = "/ "
	input.Placeholder = Text(cfg.UI.Language, "Search name, host, description or tag", "搜索名称、地址、备注或标签")
	input.CharLimit = 200
	input.Blur()
	m := Browser{recent: true, Config: cfg, Version: version, Account: account, width: 100, height: 24, query: input, color: color, groups: []string{""}}
	m.ascii = ResolveIcons(cfg.UI.Icons).Online == "[OK]"
	m.latencies = map[string]LatencyResult{}
	seen := map[string]bool{}
	for _, s := range cfg.Servers {
		if s != nil && s.Group != "" {
			seen[s.Group] = true
		}
	}
	for g := range seen {
		m.groups = append(m.groups, g)
	}
	sort.Strings(m.groups[1:])
	m.filter()
	for i, alias := range m.visible {
		if alias == initial {
			m.cursor = i
			break
		}
	}
	m.keepVisible()
	return m
}

func (m Browser) Init() tea.Cmd { return tickBrowser() }

func (m Browser) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case browserTick:
		return m, tickBrowser()
	case LatencyResult:
		if !m.pending[msg.Alias] {
			return m, nil
		}
		delete(m.pending, msg.Alias)
		m.latencies[msg.Alias] = msg
		m.probing = max(0, m.probing-1)
		if len(m.probeQueue) > 0 {
			alias := m.probeQueue[0]
			m.probeQueue = m.probeQueue[1:]
			m.probing++
			return m, m.Probe(alias)
		}
	case tea.WindowSizeMsg:
		m.width = max(1, msg.Width)
		m.height = max(1, msg.Height)
		m.query.Width = max(1, m.width-8)
		m.keepVisible()
	case tea.KeyMsg:
		key := msg.String()
		if key == "ctrl+c" {
			m.Action = "quit"
			return m, tea.Quit
		}
		// Terminals may deliver pasted or rapidly typed search text in one event.
		// Never interpret pasted letters as destructive/navigation shortcuts.
		if !m.query.Focused() && msg.Type == tea.KeyRunes && len(msg.Runes) > 1 {
			focus := m.query.Focus()
			msg.Runes = []rune(strings.TrimPrefix(string(msg.Runes), "/"))
			var input tea.Cmd
			m.query, input = m.query.Update(msg)
			m.cursor = 0
			m.offset = 0
			m.filter()
			return m, tea.Batch(focus, input)
		}
		if m.query.Focused() {
			if key == "esc" || key == "enter" {
				m.query.Blur()
				return m, nil
			}
			var cmd tea.Cmd
			m.query, cmd = m.query.Update(msg)
			m.cursor = 0
			m.offset = 0
			m.filter()
			return m, cmd
		}
		switch key {
		case "/":
			cmd := m.focusSearch()
			return m, cmd
		case "q":
			m.Action = "quit"
			return m, tea.Quit
		case "esc":
			if m.query.Value() != "" {
				m.query.SetValue("")
				m.cursor = 0
				m.filter()
			} else {
				m.Action = "quit"
				return m, tea.Quit
			}
		case "up", "k":
			m.cursor--
		case "down", "j":
			m.cursor++
		case "pgup", "ctrl+u":
			m.cursor -= m.capacity()
		case "pgdown", "ctrl+d":
			m.cursor += m.capacity()
		case "home":
			m.cursor = 0
		case "end":
			m.cursor = len(m.visible) - 1
		case "g":
			m.group = (m.group + 1) % len(m.groups)
			m.cursor = 0
			m.offset = 0
			m.filter()
		case "s":
			m.recent = !m.recent
			m.cursor = 0
			m.offset = 0
			m.filter()
		case "?":
			m.help = !m.help
		case "p":
			if m.Probe != nil && m.probing == 0 {
				m.pending = map[string]bool{}
				for _, alias := range m.visible {
					m.pending[alias] = true
					delete(m.latencies, alias)
				}
				m.probeQueue = append([]string(nil), m.visible...)
				var commands []tea.Cmd
				for len(m.probeQueue) > 0 && m.probing < 6 {
					alias := m.probeQueue[0]
					m.probeQueue = m.probeQueue[1:]
					m.probing++
					commands = append(commands, m.Probe(alias))
				}
				return m, tea.Batch(commands...)
			}
		case "a":
			m.Action = "add"
			return m, tea.Quit
		case "x":
			m.Action = "cleanup"
			return m, tea.Quit
		case "r":
			m.Action = "refresh"
			return m, tea.Quit
		case "enter", "c":
			if len(m.visible) > 0 {
				m.Choice = m.visible[m.cursor]
				m.Action = "manage"
				if key == "c" {
					m.Action = "connect"
				}
				return m, tea.Quit
			}
		}
		m.keepVisible()
	default:
		if m.query.Focused() {
			var cmd tea.Cmd
			m.query, cmd = m.query.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m *Browser) focusSearch() tea.Cmd { return m.query.Focus() }

func (m *Browser) filter() {
	m.visible = nil
	terms := strings.Fields(strings.ToLower(m.query.Value()))
	for alias, s := range m.Config.Servers {
		if s == nil || (m.groups[m.group] != "" && s.Group != m.groups[m.group]) {
			continue
		}
		hay := strings.ToLower(SanitizeTerminalText(strings.Join([]string{alias, s.Label, s.Host, s.User, s.Platform, s.Group, config.EffectiveDescription(s), strings.Join(s.Tags, " ")}, " ")))
		match := true
		for _, term := range terms {
			if !strings.Contains(hay, term) {
				match = false
				break
			}
		}
		if match {
			m.visible = append(m.visible, alias)
		}
	}
	sort.Slice(m.visible, func(i, j int) bool {
		a, b := m.visible[i], m.visible[j]
		if m.recent && !m.Config.Servers[a].LastUsed.Equal(m.Config.Servers[b].LastUsed) {
			return m.Config.Servers[a].LastUsed.After(m.Config.Servers[b].LastUsed)
		}
		return a < b
	})
	m.keepVisible()
}

func (m Browser) capacity() int { return max(1, m.height-11) }
func (m *Browser) keepVisible() {
	m.cursor = max(0, min(m.cursor, len(m.visible)-1))
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+m.capacity() {
		m.offset = m.cursor - m.capacity() + 1
	}
	m.offset = max(0, min(m.offset, max(0, len(m.visible)-m.capacity())))
}

func (m Browser) paint(value, role string) string {
	if !m.color {
		return value
	}
	s := lipgloss.NewStyle()
	switch role {
	case "brand":
		s = s.Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "30", Dark: "80"})
	case "muted":
		s = s.Foreground(lipgloss.AdaptiveColor{Light: "243", Dark: "245"})
	case "selected":
		s = s.Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "23", Dark: "159"}).Background(lipgloss.AdaptiveColor{Light: "159", Dark: "236"})
	case "rule":
		s = s.Foreground(lipgloss.AdaptiveColor{Light: "250", Dark: "238"})
	case "heading":
		s = s.Bold(true)
	}
	return s.Render(value)
}

func (m Browser) View() string {
	w := max(1, m.width-4)
	if m.height < 10 || m.width < 28 {
		return m.fit([]string{"SSHM", m.tr("Terminal too small", "终端太小"), m.tr("Resize to 28 x 10", "请放大至 28 × 10"), m.tr("q quit", "q 退出")})
	}
	account := m.tr("Local only", "本地模式")
	if m.Account != "" {
		account = m.tr("Cloud · ", "云端 · ") + SanitizeTerminalText(m.Account)
	}
	left := m.tr("SSHM  /  Servers", "SSHM  /  服务器")
	leftWidth := max(1, w-lipgloss.Width(account)-2)
	header := m.paint(PadRightWidth(left, leftWidth), "brand") + "  " + m.paint(TruncateWidth(account, w-leftWidth-2), "muted")
	if w < 60 {
		header = m.paint(m.tr("SSHM  /  Servers", "SSHM  /  服务器"), "brand")
	}
	group := m.tr("All groups", "全部分组")
	if m.groups[m.group] != "" {
		group = SanitizeTerminalText(m.groups[m.group])
	}
	order := m.tr("Name", "名称")
	if m.recent {
		order = m.tr("Recently used", "最近使用")
	}
	meta := fmt.Sprintf(m.tr("LOCAL INVENTORY  ·  %d connections", "本机列表  ·  %d 个连接"), len(m.Config.Servers))
	if w >= 90 {
		meta += "  ·  v" + SanitizeTerminalText(m.Version)
	} else {
		meta = "v" + SanitizeTerminalText(m.Version)
		if w >= 50 {
			meta += fmt.Sprintf(m.tr("  ·  %d servers", "  ·  %d 台服务器"), len(m.Config.Servers))
		}
	}
	search := m.query.View()
	if !m.query.Focused() {
		search = m.tr("/ Search servers", "/ 搜索服务器")
		if m.query.Value() != "" {
			search = "/ " + SanitizeTerminalText(m.query.Value())
		}
	}
	lines := []string{header, m.paint(meta, "muted"), "", m.paint(search, "brand"), m.paint(fmt.Sprintf(m.tr("%d results   ·   %s   ·   %s", "%d 个结果   ·   %s   ·   %s"), len(m.visible), group, order), "muted"), m.paint(strings.Repeat("─", w), "rule")}
	listWidth := w
	wide := w >= 96 && m.height >= 20
	if wide {
		listWidth = w * 3 / 5
	}
	lines = append(lines, m.paint(m.metricRow(m.tr("SERVER", "服务器"), m.tr("LAST USED", "上次连接"), "TCP", listWidth), "muted"))
	details := []string{}
	if wide && len(m.visible) > 0 {
		details = m.details(w - listWidth - 3)
	}
	for row := 0; row < m.capacity(); row++ {
		index := m.offset + row
		cell := strings.Repeat(" ", listWidth)
		if index < len(m.visible) {
			alias := m.visible[index]
			s := m.Config.Servers[alias]
			mark := " "
			if index == m.cursor {
				mark = "›"
			}
			name := SanitizeTerminalText(alias)
			if alias == m.Config.Default {
				name += " *"
			}
			state := "·"
			if s.LastStatus == config.StatusOnline {
				state = "●"
			} else if s.LastStatus == config.StatusOffline {
				state = "○"
			}
			cell = m.metricRow(mark+" "+state+" "+name, m.since(s.LastUsed), m.latency(alias), listWidth)
			if index == m.cursor {
				cell = m.paint(cell, "selected")
			}
		} else if len(m.visible) == 0 && row == 1 {
			cell = PadRightWidth(m.tr("No matches. / search · g group · a add", "没有匹配。/ 搜索 · g 分组 · a 添加"), listWidth)
			if len(m.Config.Servers) == 0 {
				cell = PadRightWidth(m.tr("No servers yet. Press a to add one.", "还没有服务器。按 a 添加。"), listWidth)
			}
		}
		if wide {
			detail := ""
			if row < len(details) {
				detail = details[row]
			}
			cell += " " + m.paint("│", "rule") + " " + detail
		}
		lines = append(lines, cell)
	}
	position := 0
	if len(m.visible) > 0 {
		position = m.cursor + 1
	}
	footer := fmt.Sprintf(m.tr("%d/%d   ↑↓ move   Enter manage   c connect   / search   ? help", "%d/%d   ↑↓ 选择   Enter 管理   c 连接   / 搜索   ? 帮助"), position, len(m.visible))
	if w >= 75 {
		footer = fmt.Sprintf(m.tr("%d/%d  ↑↓ move  Enter manage  c SSH  / search  p probe TCP  ? help", "%d/%d  ↑↓ 选择  Enter 管理  c 连接  / 搜索  p 测速  ? 帮助"), position, len(m.visible))
	}
	if w < 75 {
		footer = fmt.Sprintf(m.tr("%d/%d  ↑↓ move  Enter open  / find  ? help", "%d/%d  ↑↓ 选择  Enter 打开  / 搜索  ? 帮助"), position, len(m.visible))
	}
	if m.query.Focused() {
		footer = m.tr("Type to filter   Enter / Esc finish search   Ctrl+C quit", "输入筛选条件   Enter / Esc 结束搜索   Ctrl+C 返回")
		if w < 60 {
			footer = m.tr("Enter / Esc finish   Ctrl+C quit", "Enter / Esc 完成   Ctrl+C 返回")
		}
	}
	if m.help {
		footer = m.tr("a add  g group  s sort  p probe TCP  r reload  x cleanup  q quit", "a 添加  g 分组  s 排序  p 测速  r 刷新  x 清理  q 返回")
		if w < 60 {
			footer = m.tr("a add  p TCP  g group  q quit", "a 添加  p 测速  g 分组  q 返回")
		}
	}
	if m.probing > 0 {
		footer = fmt.Sprintf(m.tr("Probing TCP · %d remaining · search and navigation stay available", "正在测速 · 剩余 %d · 可继续搜索和操作"), m.probing+len(m.probeQueue))
	}
	lines = append(lines, m.paint(strings.Repeat("─", w), "rule"), m.paint(footer, "muted"))
	return m.fit(lines)
}

func (m Browser) metricRow(name, age, latency string, width int) string {
	if width < 34 {
		return PadRightWidth(name, max(1, width-11)) + "  " + PadRightWidth(age, 9)
	}
	return PadRightWidth(name, width-22) + "  " + PadRightWidth(age, 9) + "  " + PadRightWidth(latency, 9)
}

func (m Browser) latency(alias string) string {
	if r, ok := m.latencies[alias]; ok {
		if r.Skipped {
			return m.tr("via route", "经由代理")
		}
		if r.Failed {
			return m.tr("no reply", "无响应")
		}
		if r.Duration < time.Millisecond {
			return "<1ms"
		}
		return fmt.Sprintf("%dms", r.Duration.Milliseconds())
	}
	if m.pending[alias] {
		return "..."
	}
	return "—"
}

func (m Browser) details(width int) []string {
	a := m.visible[m.cursor]
	s := m.Config.Servers[a]
	text := func(s string) string { return TruncateWidth(SanitizeTerminalText(s), width) }
	group := s.Group
	if group == "" {
		group = m.tr("Ungrouped", "未分组")
	}
	status := s.LastStatus
	if status == "" {
		status = m.tr("unknown", "未知")
	}
	if s.LastSSHError != "" {
		status += " · " + s.LastSSHError
	}
	connection := fmt.Sprintf("%s@%s:%d", s.User, s.Host, s.Port)
	if config.DeviceConnectionID(s) != "" {
		connection = m.tr("SSHM client · end-to-end encrypted", "SSHM 客户端 · 端到端加密")
	}
	rows := []string{m.paint(text(a), "heading"), m.paint(text(config.EffectiveDescription(s)), "muted"), "", m.paint(m.tr("CONNECTION", "连接"), "muted"), text(connection), text(platformLabel(s.Platform) + " · " + s.Auth), "", m.paint(m.tr("ORGANIZATION", "分组和标签"), "muted"), text(group), text(strings.Join(s.Tags, " · ")), "", m.paint(m.tr("LAST OBSERVED", "最近检测"), "muted"), text(status + m.tr(" · last connection ", " · 上次连接 ") + m.since(s.LastUsed)), text(m.tr("TCP connect: ", "TCP 延迟：") + m.latency(a))}
	client := s.SSHMVersion
	switch s.SSHMStatus {
	case "missing":
		client = m.tr("not installed", "未安装")
	case "installed":
		if client == "" {
			client = m.tr("installed · version unknown", "已安装 · 版本未知")
		}
	default:
		client = m.tr("not checked / unavailable", "未检测 / 无法获取")
	}
	rows = append(rows, "", m.paint(m.tr("SSHM CLIENT", "SSHM 客户端"), "muted"), text(client))
	return rows
}

func (m Browser) fit(lines []string) string {
	// ANSI-aware truncation is essential for selections and CJK text on resize.
	width := max(1, m.width-4)
	padding := strings.Repeat(" ", min(2, max(0, m.width-1)))
	for i := range lines {
		if m.ascii {
			lines[i] = strings.NewReplacer("●", "+", "○", "o", "·", ".", "─", "-", "│", "|", "›", ">", "↑↓", "j/k", "—", "-").Replace(lines[i])
		}
		if !m.color {
			lines[i] = stripANSI(lines[i])
		}
		lines[i] = padding + clipANSI(lines[i], min(width, m.width-len(padding)))
		if m.ascii {
			lines[i] = strings.ReplaceAll(lines[i], "…", "~")
		}
	}
	return strings.Join(lines[:min(len(lines), max(1, m.height-1))], "\n")
}

func (m Browser) tr(en, zh string) string { return Text(m.Config.UI.Language, en, zh) }

func (m Browser) since(t time.Time) string {
	if ResolveLanguage(m.Config.UI.Language) != "zh-CN" {
		return humanizeSince(t)
	}
	if t.IsZero() || time.Since(t) < 0 {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d小时前", int(d.Hours()))
	default:
		return fmt.Sprintf("%d天前", int(d.Hours()/24))
	}
}
