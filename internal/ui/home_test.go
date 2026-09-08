package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestHomeResponsiveLanguagesAndAccountCounts(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		for _, size := range [][2]int{{120, 30}, {80, 24}, {40, 18}, {30, 15}, {12, 6}} {
			cfg := config.New()
			cfg.UI.Language = lang
			cfg.UI.Icons = "ascii"
			h := NewHome(cfg, HomeSummary{Account: "user\x1b[2J", Total: 12, Local: 3, Linked: 9, Cloud: 10, CloudKnown: true, Synced: "09-08 12:00"}, "0.8.0-test", false)
			m, _ := h.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			h = m.(Home)
			for i := 0; i < 9; i++ {
				view := h.View()
				require.NotContains(t, view, "\x1b")
				lines := strings.Split(view, "\n")
				require.LessOrEqual(t, len(lines), size[1])
				for _, line := range lines {
					require.LessOrEqual(t, lipgloss.Width(line), size[0])
				}
				m, _ = h.Update(tea.KeyMsg{Type: tea.KeyDown})
				h = m.(Home)
			}
			if size[0] >= 80 {
				view := h.View()
				require.Contains(t, view, "12")
				require.Contains(t, view, "10")
				require.Contains(t, view, "09-08 12:00")
				if lang == "zh-CN" {
					require.Contains(t, view, "保险库已锁定")
				}
			}
		}
	}
}
func TestHomeShortcutsCannotMutateOrLoginWithoutExplicitSelection(t *testing.T) {
	cfg := config.New()
	cfg.UI.Language = "en"
	h := NewHome(cfg, HomeSummary{}, "test", false)
	for _, key := range []string{"login", "logout", "sync"} {
		m, cmd := h.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		require.Empty(t, m.(Home).Action)
		require.Nil(t, cmd)
	}
	m, _ := h.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("l")})
	require.Equal(t, "account", m.(Home).Action)
	require.Contains(t, h.View(), "not logged in")
	require.NotContains(t, h.View(), "Vault locked")
	m, _ = h.Update(ReleaseStatus{Verified: true, Available: true, Latest: "0.9.0"})
	require.Contains(t, m.(Home).View(), "0.9.0")
	require.Empty(t, m.(Home).Action, "new version must not auto-install")
}
func TestLanguagePrecedence(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "en_US.UTF-8")
	require.Equal(t, "zh-CN", ResolveLanguage("auto"))
	require.Equal(t, "en", ResolveLanguage("en"))
	t.Setenv("LC_ALL", "C")
	require.Equal(t, "en", ResolveLanguage("auto"))
}
