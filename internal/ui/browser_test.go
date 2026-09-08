package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func browserFixture() *config.Config {
	c := &config.Config{Servers: map[string]*config.Server{}}
	c.UI.Icons = "unicode"
	for i := 0; i < 50; i++ {
		c.Servers[fmt.Sprintf("server-%02d", i)] = &config.Server{Host: "example.invalid", User: "ops", Port: 22, Auth: "key", Description: "中文服务器 · a long description for responsive terminals", Group: []string{"Development", "Production"}[i%2], Tags: []string{"region-asia"}, LastUsed: time.Unix(int64(i), 0)}
	}
	return c
}

func browserKey(m Browser, key string) Browser {
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	switch key {
	case "enter":
		msg.Type = tea.KeyEnter
	case "esc":
		msg.Type = tea.KeyEsc
	case "end":
		msg.Type = tea.KeyEnd
	case "down":
		msg.Type = tea.KeyDown
	}
	v, _ := m.Update(msg)
	return v.(Browser)
}

func TestBrowserProbesAreExplicitBoundedAndDoNotRecordSSHUse(t *testing.T) {
	cfg := browserFixture()
	lastUsed := cfg.Servers["server-00"].LastUsed
	m := NewBrowser(cfg, "", "test", "", false)
	var started []string
	m.Probe = func(alias string) tea.Cmd {
		started = append(started, alias)
		return func() tea.Msg { return LatencyResult{Alias: alias, Duration: 12 * time.Millisecond} }
	}
	m = browserKey(m, "down")
	require.Empty(t, started)
	m = browserKey(m, "p")
	require.Len(t, started, 6)
	require.Len(t, m.pending, 50)
	m = browserKey(m, "p")
	require.Len(t, started, 6, "repeated p must not start overlapping batches")
	m = browserKey(m, "/")
	m = browserKey(m, "p")
	require.True(t, m.query.Focused())
	require.Equal(t, "p", m.query.Value())
	for i := 0; i < 50; i++ {
		alias := started[i]
		next, _ := m.Update(LatencyResult{Alias: alias, Duration: 12 * time.Millisecond})
		m = next.(Browser)
		require.LessOrEqual(t, m.probing, 6)
	}
	require.Empty(t, m.pending)
	require.Zero(t, m.probing)
	require.Equal(t, "12ms", m.latency("server-00"))
	require.Equal(t, lastUsed, cfg.Servers["server-00"].LastUsed)
}

func TestBrowserProbeOnlyFilteredServersAndShowAge(t *testing.T) {
	cfg := browserFixture()
	cfg.Servers["server-49"].LastUsed = time.Now().Add(-2 * time.Hour)
	m := NewBrowser(cfg, "server-49", "test", "", false)
	m.Probe = func(alias string) tea.Cmd {
		return func() tea.Msg { return LatencyResult{Alias: alias, Skipped: true} }
	}
	m = browserKey(m, "/server-49")
	m = browserKey(m, "enter")
	m = browserKey(m, "p")
	require.Equal(t, "...", m.latency("server-49"))
	require.Equal(t, "—", m.latency("server-01"))
	next, _ := m.Update(LatencyResult{Alias: "server-49", Skipped: true})
	m = next.(Browser)
	require.Contains(t, m.View(), "2h ago")
	require.Contains(t, m.View(), "via route")
	m.latencies["server-49"] = LatencyResult{Failed: true}
	require.Equal(t, "no reply", m.latency("server-49"))
}

func TestBrowserSearchDoesNotExecuteShortcutKeys(t *testing.T) {
	m := NewBrowser(browserFixture(), "", "test", "", false)
	m = browserKey(m, "/")
	require.True(t, m.query.Focused())
	m = browserKey(m, "server-49")
	require.Equal(t, []string{"server-49"}, m.visible)
	m = browserKey(m, "q")
	require.Empty(t, m.Action, "q must remain search text while typing")
	require.Empty(t, m.visible)
	m = browserKey(m, "enter")
	require.False(t, m.query.Focused())
	require.Empty(t, m.Action, "finishing search must not connect")
	m = browserKey(m, "esc")
	require.Len(t, m.visible, 50)
}

func TestBrowserAcceptsSearchInSingleTerminalEvent(t *testing.T) {
	m := NewBrowser(browserFixture(), "", "test", "", false)
	m = browserKey(m, "/server-49")
	require.True(t, m.query.Focused())
	require.Equal(t, []string{"server-49"}, m.visible)
	require.Empty(t, m.Action)
}

func TestBrowserResizeScrollAndGroupReachEveryEntry(t *testing.T) {
	m := NewBrowser(browserFixture(), "", "test", "", false)
	m = browserKey(m, "end")
	require.Equal(t, 49, m.cursor)
	for _, size := range [][2]int{{120, 32}, {80, 24}, {40, 12}, {28, 10}, {10, 4}, {1, 1}} {
		v, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = v.(Browser)
		view := m.View()
		require.LessOrEqual(t, len(strings.Split(view, "\n")), max(1, size[1]-1))
		for _, line := range strings.Split(view, "\n") {
			require.LessOrEqual(t, lipgloss.Width(line), size[0])
		}
		if size[0] >= 28 && size[1] >= 10 {
			require.Contains(t, view, "server-00")
		}
	}
	m = browserKey(m, "g")
	require.Len(t, m.visible, 25)
	for _, a := range m.visible {
		require.Equal(t, "Development", m.Config.Servers[a].Group)
	}
	m = browserKey(m, "s")
	require.Equal(t, "server-00", m.visible[0])
}

func TestBrowserSelectionAndEmptyInventory(t *testing.T) {
	m := NewBrowser(browserFixture(), "server-17", "test", "", false)
	m = browserKey(m, "c")
	require.Equal(t, "connect", m.Action)
	require.Equal(t, "server-17", m.Choice)
	m = NewBrowser(&config.Config{Servers: map[string]*config.Server{}}, "", "test", "", false)
	m = browserKey(m, "enter")
	require.Empty(t, m.Action)
	require.Contains(t, m.View(), "No servers yet")
	m = browserKey(m, "a")
	require.Equal(t, "add", m.Action)
}

func TestBrowserASCIIChromeForLegacyTerminals(t *testing.T) {
	c := browserFixture()
	c.UI.Icons = "ascii"
	m := NewBrowser(c, "", "test", "", false)
	m.width = 120
	view := m.View()
	for _, glyph := range []string{"●", "○", "─", "│", "›", "↑↓", "…"} {
		require.NotContains(t, view, glyph)
	}
	require.Contains(t, view, "j/k")
}

func TestBrowserRenderingSanitizesMetadataAndPrefersDescription(t *testing.T) {
	c := browserFixture()
	c.Servers["server-00"].Description = "danger\x1b]52;c;YQ==\a description"
	c.Servers["server-00"].Notes = "private-notes-never-render"
	c.Servers["server-00"].KeyPath = "private-key-path-never-render"
	m := NewBrowser(c, "server-00", "test", "user\x1b[2J", false)
	m.width = 140
	m.height = 32
	view := m.View()
	require.NotContains(t, view, "\x1b")
	require.NotContains(t, view, "private-notes-never-render")
	require.NotContains(t, view, "private-key-path-never-render")
	require.Contains(t, view, "LAST OBSERVED")
	require.Contains(t, view, "Cloud · user")
}

func TestBrowserShowsVersionInNarrowWindow(t *testing.T) {
	for _, width := range []int{28, 40, 80, 120} {
		m := NewBrowser(browserFixture(), "", "0.8.0-cloud-preview.8", "", false)
		next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: 24})
		require.Contains(t, next.View(), "v0.8.0-cloud-preview.8")
	}
}

func TestListsDefaultToRecentSuccessfulConnections(t *testing.T) {
	cfg := config.New()
	cfg.Servers["a-never"] = &config.Server{}
	cfg.Servers["b-older"] = &config.Server{LastUsed: time.Now().Add(-time.Hour)}
	cfg.Servers["z-recent"] = &config.Server{LastUsed: time.Now()}
	cfg.Servers["a-tie"] = &config.Server{LastUsed: cfg.Servers["z-recent"].LastUsed}
	// A fresh probe must not place a never-connected server first.
	cfg.Servers["a-never"].LastChecked = time.Now()
	m := NewBrowser(cfg, "", "test", "", false)
	require.Equal(t, []string{"a-tie", "z-recent", "b-older", "a-never"}, m.visible)
	rendered := RenderServerTable(cfg.Servers, ResolveIcons("ascii"), false)
	require.Less(t, strings.Index(rendered, "a-tie"), strings.Index(rendered, "z-recent"))
	require.Less(t, strings.Index(rendered, "z-recent"), strings.Index(rendered, "b-older"))
	require.Less(t, strings.Index(rendered, "b-older"), strings.Index(rendered, "a-never"))
}
