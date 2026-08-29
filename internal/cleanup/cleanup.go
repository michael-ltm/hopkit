// Package cleanup classifies inventory entries for safe, human-reviewed
// cleanup. It never deletes servers or keys itself.
package cleanup

import (
	"sort"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
)

const (
	ReasonIdle            = "idle"
	ReasonNeverUsed       = "never_used"
	ReasonIdentityChanged = "identity_changed"
	ReasonHistoryUnknown  = "history_unknown"
)

type Entry struct {
	Alias             string     `json:"alias"`
	Platform          string     `json:"platform,omitempty"`
	Description       string     `json:"description,omitempty"`
	CreatedAt         *time.Time `json:"created_at,omitempty"`
	IdentityChangedAt *time.Time `json:"identity_changed_at,omitempty"`
	LastUsed          *time.Time `json:"last_used,omitempty"`
	LastSeen          *time.Time `json:"last_seen,omitempty"`
	LastChecked       *time.Time `json:"last_checked,omitempty"`
	LastStatus        string     `json:"last_status,omitempty"`
	IdleDays          int        `json:"idle_days,omitempty"`
	Reason            string     `json:"reason"`
	ProtectionReasons []string   `json:"protection_reasons,omitempty"`
}

type Report struct {
	GeneratedAt   time.Time `json:"generated_at"`
	OlderThanDays int       `json:"older_than_days"`
	Candidates    []Entry   `json:"candidates"`
	Unknown       []Entry   `json:"unknown_history"`
	Protected     []Entry   `json:"protected"`
}

// Review returns deterministic cleanup candidates. Legacy entries with no
// CreatedAt and no LastUsed stay in Unknown unless includeUnknown is explicit.
func Review(cfg *config.Config, now time.Time, olderThanDays int, includeUnknown bool) Report {
	if olderThanDays < 1 {
		olderThanDays = 90
	}
	now = now.UTC()
	cutoff := now.Add(-time.Duration(olderThanDays) * 24 * time.Hour)
	report := Report{GeneratedAt: now, OlderThanDays: olderThanDays}
	if cfg == nil {
		return report
	}
	for alias, server := range cfg.Servers {
		if server == nil {
			continue
		}
		entry, eligible := classify(alias, server, now, cutoff)
		if !eligible {
			continue
		}
		entry.ProtectionReasons = config.CleanupProtectionReasons(cfg, alias)
		if len(entry.ProtectionReasons) > 0 {
			report.Protected = append(report.Protected, entry)
			continue
		}
		if entry.Reason == ReasonHistoryUnknown && !includeUnknown {
			report.Unknown = append(report.Unknown, entry)
			continue
		}
		report.Candidates = append(report.Candidates, entry)
	}
	for _, entries := range []*[]Entry{&report.Candidates, &report.Unknown, &report.Protected} {
		sort.Slice(*entries, func(i, j int) bool { return (*entries)[i].Alias < (*entries)[j].Alias })
	}
	return report
}

func classify(alias string, server *config.Server, now, cutoff time.Time) (Entry, bool) {
	entry := Entry{
		Alias: alias, Platform: server.Platform,
		// Cleanup reports can be emitted as JSON. Do not fall back to legacy
		// Notes here: notes are private operational text, while Description is
		// explicitly inventory-visible metadata.
		Description: server.Description,
		CreatedAt:   optionalTime(server.CreatedAt), LastUsed: optionalTime(server.LastUsed),
		IdentityChangedAt: optionalTime(server.IdentityChangedAt),
		LastSeen:          optionalTime(server.LastSeen), LastChecked: optionalTime(server.LastChecked),
		LastStatus: server.LastStatus,
	}
	baseline := server.CreatedAt
	unusedReason := ReasonNeverUsed
	if server.IdentityChangedAt.After(baseline) {
		baseline = server.IdentityChangedAt
		unusedReason = ReasonIdentityChanged
	}
	switch {
	case server.LastUsed.IsZero() && baseline.IsZero():
		entry.Reason = ReasonHistoryUnknown
		return entry, true
	case server.LastUsed.IsZero():
		if baseline.After(cutoff) {
			return Entry{}, false
		}
		entry.Reason = unusedReason
		entry.IdleDays = wholeDays(now.Sub(baseline))
		return entry, true
	case !server.LastUsed.After(cutoff):
		entry.Reason = ReasonIdle
		entry.IdleDays = wholeDays(now.Sub(server.LastUsed))
		return entry, true
	default:
		return Entry{}, false
	}
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func wholeDays(duration time.Duration) int {
	if duration <= 0 {
		return 0
	}
	return int(duration / (24 * time.Hour))
}
