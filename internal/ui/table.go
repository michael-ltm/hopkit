package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/michael-ltm/sshm/internal/config"
)

// RenderServerTable returns a colorized table of servers. If color is false,
// styles are stripped (test mode, --no-color, non-tty).
func RenderServerTable(servers map[string]*config.Server, ic IconSet, color bool) string {
	if len(servers) == 0 {
		return "No servers yet. Add one with: sshm add\n"
	}

	aliases := make([]string, 0, len(servers))
	for a := range servers {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	rows := [][]string{{"ID", "STATUS", "HOST", "USER", "AUTH", "TAGS", "LAST SEEN"}}
	for _, a := range aliases {
		s := servers[a]
		statusIcon, statusStyle := statusGlyph(s.LastStatus, ic)
		authIcon := authGlyph(s.Auth, ic)
		row := []string{
			a,
			renderCell(statusIcon+" "+s.LastStatus, statusStyle, color),
			s.Host,
			s.User,
			authIcon,
			strings.Join(s.Tags, ", "),
			humanizeSince(s.LastSeen),
		}
		rows = append(rows, row)
	}

	return formatTable(rows, color)
}

func statusGlyph(s string, ic IconSet) (string, lipgloss.Style) {
	switch s {
	case config.StatusOnline:
		return ic.Online, StyleOnline
	case config.StatusOffline:
		return ic.Offline, StyleOffline
	case config.StatusUnknown, "":
		return ic.Unknown, StyleUnknown
	default:
		return ic.None, StyleNone
	}
}

func authGlyph(a string, ic IconSet) string {
	switch a {
	case config.AuthKey:
		return ic.AuthKey + " key"
	case config.AuthPassword:
		return ic.AuthPassword + " pwd"
	case config.AuthAgent:
		return ic.AuthAgent + " agent"
	default:
		return "—"
	}
}

func humanizeSince(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func renderCell(text string, style lipgloss.Style, color bool) string {
	if !color {
		return text
	}
	return style.Render(text)
}

// formatTable lays out rows[0] as header, rest as data, with column widths
// driven by content. No external dependency.
func formatTable(rows [][]string, color bool) string {
	if len(rows) == 0 {
		return ""
	}
	cols := len(rows[0])
	widths := make([]int, cols)
	for _, r := range rows {
		for i, c := range r {
			// strip ANSI for width calc
			w := lipgloss.Width(c)
			if w > widths[i] {
				widths[i] = w
			}
		}
	}

	var b strings.Builder
	for ri, r := range rows {
		for i, c := range r {
			cell := c
			if ri == 0 && color {
				cell = StyleHeader.Render(c)
			}
			pad := widths[i] - lipgloss.Width(c)
			if pad < 0 {
				pad = 0
			}
			b.WriteString(cell)
			b.WriteString(strings.Repeat(" ", pad))
			if i < cols-1 {
				b.WriteString("  ")
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}
