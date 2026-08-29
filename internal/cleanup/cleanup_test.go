package cleanup

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestReviewSeparatesIdleUnknownRecentAndProtected(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	cfg := config.New()
	cfg.Default = "default-old"
	cfg.Servers["idle"] = &config.Server{LastUsed: now.Add(-100 * 24 * time.Hour)}
	cfg.Servers["never"] = &config.Server{CreatedAt: now.Add(-120 * 24 * time.Hour)}
	cfg.Servers["recent"] = &config.Server{LastUsed: now.Add(-2 * 24 * time.Hour)}
	cfg.Servers["legacy"] = &config.Server{}
	cfg.Servers["default-old"] = &config.Server{LastUsed: now.Add(-200 * 24 * time.Hour)}

	report := Review(cfg, now, 90, false)
	require.Equal(t, []string{"idle", "never"}, aliases(report.Candidates))
	require.Equal(t, []string{"legacy"}, aliases(report.Unknown))
	require.Equal(t, []string{"default-old"}, aliases(report.Protected))
	require.Equal(t, 100, report.Candidates[0].IdleDays)

	withUnknown := Review(cfg, now, 90, true)
	require.Equal(t, []string{"idle", "legacy", "never"}, aliases(withUnknown.Candidates))
}

func TestReviewJSONOmitsUnknownZeroTimes(t *testing.T) {
	cfg := config.New()
	cfg.Servers["legacy"] = &config.Server{Notes: "private legacy note must not enter cleanup JSON"}
	report := Review(cfg, time.Now(), 90, true)
	data, err := json.Marshal(report)
	require.NoError(t, err)
	require.NotContains(t, string(data), "0001-01-01")
	require.NotContains(t, string(data), "created_at")
	require.NotContains(t, string(data), "last_used")
	require.NotContains(t, string(data), "private legacy note")
}

func TestReviewCutoffIsInclusive(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	cfg := config.New()
	cfg.Servers["edge"] = &config.Server{LastUsed: now.Add(-90 * 24 * time.Hour)}
	require.Equal(t, []string{"edge"}, aliases(Review(cfg, now, 90, false).Candidates))
}

func TestReviewUsesIdentityChangeAsFreshCleanupBaseline(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	cfg := config.New()
	cfg.Servers["repointed"] = &config.Server{
		CreatedAt: now.Add(-500 * 24 * time.Hour), IdentityChangedAt: now.Add(-2 * 24 * time.Hour),
	}

	require.Empty(t, Review(cfg, now, 90, false).Candidates)
	later := now.Add(90 * 24 * time.Hour)
	report := Review(cfg, later, 90, false)
	require.Equal(t, []string{"repointed"}, aliases(report.Candidates))
	require.Equal(t, ReasonIdentityChanged, report.Candidates[0].Reason)
	require.Equal(t, 92, report.Candidates[0].IdleDays)
}

func aliases(entries []Entry) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.Alias
	}
	return result
}
