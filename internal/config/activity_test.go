package config

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRecordSSHUseAndProbeKeepUsageSemanticsSeparate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := New()
	cfg.Servers["host"] = &Server{Host: "host", Port: 22, User: "u", Auth: AuthAgent}
	require.NoError(t, Save(path, cfg))

	used := time.Date(2026, 8, 1, 2, 3, 4, 0, time.FixedZone("local", 8*3600))
	require.NoError(t, RecordSSHUse(path, "host", cfg.Servers["host"], used))
	checked := used.Add(24 * time.Hour)
	require.NoError(t, RecordProbes(path, map[string]ProbeObservation{
		"host": NewProbeObservation(cfg.Servers["host"], false, checked),
	}))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, used.UTC(), got.Servers["host"].LastUsed)
	require.Equal(t, used.UTC(), got.Servers["host"].LastSeen)
	require.Equal(t, checked.UTC(), got.Servers["host"].LastChecked)
	require.Equal(t, StatusOffline, got.Servers["host"].LastStatus)
}

func TestActivityIgnoresOutOfOrderStatusAndReplacedAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := New()
	original := &Server{Host: "old", Port: 22, User: "u", Auth: AuthAgent}
	cfg.Servers["host"] = original
	require.NoError(t, Save(path, cfg))

	newer := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	require.NoError(t, RecordProbes(path, map[string]ProbeObservation{
		"host": NewProbeObservation(original, false, newer),
	}))
	require.NoError(t, RecordSSHUse(path, "host", original, newer.Add(-time.Minute)))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, newer, got.Servers["host"].LastChecked)
	require.Equal(t, StatusOffline, got.Servers["host"].LastStatus)
	require.Equal(t, newer.Add(-time.Minute), got.Servers["host"].LastUsed)

	require.NoError(t, Update(path, func(latest *Config) error {
		latest.Servers["host"] = &Server{Host: "new", Port: 22, User: "u", Auth: AuthAgent}
		return nil
	}))
	require.NoError(t, RecordProbes(path, map[string]ProbeObservation{
		"host": NewProbeObservation(original, true, newer.Add(time.Minute)),
	}))
	got, err = Load(path)
	require.NoError(t, err)
	require.True(t, got.Servers["host"].LastChecked.IsZero())
}

func TestRecordProbesOrdersEachConcurrentObservationIndependently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := New()
	cfg.Servers["early"] = &Server{Host: "early", Port: 22, User: "u", Auth: AuthAgent}
	cfg.Servers["late"] = &Server{Host: "late", Port: 22, User: "u", Auth: AuthAgent}
	require.NoError(t, Save(path, cfg))

	earlyAt := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	lateAt := earlyAt.Add(time.Minute)
	require.NoError(t, RecordProbes(path, map[string]ProbeObservation{
		"early": NewProbeObservation(cfg.Servers["early"], false, earlyAt),
		"late":  NewProbeObservation(cfg.Servers["late"], true, lateAt),
	}))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, earlyAt, got.Servers["early"].LastChecked)
	require.Equal(t, lateAt, got.Servers["late"].LastChecked)
	require.Equal(t, StatusOffline, got.Servers["early"].LastStatus)
	require.Equal(t, StatusOnline, got.Servers["late"].LastStatus)
}

func TestClearServerActivityStartsNewIdentityBaseline(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	changed := time.Date(2026, 8, 29, 12, 0, 0, 0, time.FixedZone("local", 8*3600))
	server := &Server{
		CreatedAt: created, LastUsed: created, LastSeen: created,
		LastChecked: created, LastStatus: StatusOnline,
	}
	ClearServerActivity(server, changed)
	require.Equal(t, created, server.CreatedAt)
	require.Equal(t, changed.UTC(), server.IdentityChangedAt)
	require.True(t, server.LastUsed.IsZero())
	require.True(t, server.LastSeen.IsZero())
	require.True(t, server.LastChecked.IsZero())
	require.Empty(t, server.LastStatus)
}

func TestCleanupProtectionReasons(t *testing.T) {
	cfg := New()
	cfg.Default = "gateway"
	cfg.Servers["gateway"] = &Server{CleanupProtected: true}
	cfg.Servers["app"] = &Server{ProxyJump: "gateway"}
	cfg.Projects["build"] = &Project{Server: "gateway"}
	require.Equal(t, []string{
		"manually protected", "default server", "used by projects: build", "proxy jump for: app",
	}, CleanupProtectionReasons(cfg, "gateway"))
}

func TestServerLifecycleFieldsRoundTripInV5(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	cfg := New()
	cfg.Servers["pc"] = &Server{
		Host: "pc", Port: 22, User: "u", Auth: AuthKey,
		Platform: PlatformWindows, CreatedAt: now, IdentityChangedAt: now, LastUsed: now,
		LastChecked: now, LastSeen: now, LastStatus: StatusOnline,
		CleanupProtected: true,
	}
	require.NoError(t, Save(path, cfg))
	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, CurrentVersion, got.Version)
	require.Equal(t, cfg.Servers["pc"], got.Servers["pc"])
}
