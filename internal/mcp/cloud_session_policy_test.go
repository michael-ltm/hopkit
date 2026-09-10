package mcp

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/stretchr/testify/require"
)

func TestCloudSessionDefaultPolicyKeepsRecentApprovalReady(t *testing.T) {
	now := time.Now()
	s := NewCloudSession(filepath.Join(t.TempDir(), "config.toml"))
	defer s.Close()
	s.status = CloudSessionStatus{State: "ready"}
	s.authorizedAt = now.Add(-11 * time.Hour)
	s.lastUsed = now.Add(-90 * time.Minute)

	require.Equal(t, "ready", s.Status().State)
}

func TestCloudSessionDefaultPolicyExpiresAtIdleAndMaximumBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name         string
		authorizedAt time.Time
		lastUsed     time.Time
	}{
		{name: "idle", authorizedAt: time.Now(), lastUsed: time.Now().Add(-2*time.Hour - time.Second)},
		{name: "maximum age", authorizedAt: time.Now().Add(-12*time.Hour - time.Second), lastUsed: time.Now()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewCloudSession(filepath.Join(t.TempDir(), "config.toml"))
			defer s.Close()
			s.status = CloudSessionStatus{State: "ready"}
			s.authorizedAt = tc.authorizedAt
			s.lastUsed = tc.lastUsed

			require.Equal(t, "locked", s.Status().State)
		})
	}
}

func TestCloudSessionUsesConfiguredPolicy(t *testing.T) {
	s, err := NewCloudSessionWithPolicy(filepath.Join(t.TempDir(), "config.toml"), CloudSessionPolicy{
		IdleTimeout: 4 * time.Hour,
		MaximumAge:  24 * time.Hour,
	})
	require.NoError(t, err)
	defer s.Close()
	now := time.Now()
	s.status = CloudSessionStatus{State: "ready"}
	s.authorizedAt = now.Add(-23 * time.Hour)
	s.lastUsed = now.Add(-3 * time.Hour)

	require.Equal(t, "ready", s.Status().State)
	s.lastUsed = time.Now().Add(-4*time.Hour - time.Second)
	require.Equal(t, "locked", s.Status().State)
}

func TestCloudSessionPolicyRejectsUnsafeDurations(t *testing.T) {
	valid := DefaultCloudSessionPolicy()
	for _, tc := range []struct {
		name   string
		policy CloudSessionPolicy
	}{
		{name: "zero idle", policy: CloudSessionPolicy{MaximumAge: valid.MaximumAge}},
		{name: "negative idle", policy: CloudSessionPolicy{IdleTimeout: -time.Second, MaximumAge: valid.MaximumAge}},
		{name: "zero maximum", policy: CloudSessionPolicy{IdleTimeout: valid.IdleTimeout}},
		{name: "idle over thirty days", policy: CloudSessionPolicy{IdleTimeout: 30*24*time.Hour + time.Second, MaximumAge: valid.MaximumAge}},
		{name: "maximum over thirty days", policy: CloudSessionPolicy{IdleTimeout: valid.IdleTimeout, MaximumAge: 30*24*time.Hour + time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCloudSessionWithPolicy(filepath.Join(t.TempDir(), "config.toml"), tc.policy)
			require.Error(t, err)
		})
	}
}

func TestCloudSessionTokenExpiryOverridesConfiguredPolicy(t *testing.T) {
	s, err := NewCloudSessionWithPolicy(filepath.Join(t.TempDir(), "config.toml"), CloudSessionPolicy{
		IdleTimeout: 30 * 24 * time.Hour,
		MaximumAge:  30 * 24 * time.Hour,
	})
	require.NoError(t, err)
	defer s.Close()
	s.status = CloudSessionStatus{State: "ready"}
	s.authorizedAt = time.Now()
	s.lastUsed = time.Now()
	s.state = &cloudsync.State{Expires: time.Now().Add(-time.Second).UnixMilli()}

	require.Equal(t, "locked", s.Status().State)
}

func TestCloudSessionApprovalShowsConfiguredPolicy(t *testing.T) {
	f := newBrowserFixture(t)
	s, err := NewCloudSessionWithPolicy(f.path, CloudSessionPolicy{
		IdleTimeout: 3 * time.Hour,
		MaximumAge:  18 * time.Hour,
	})
	require.NoError(t, err)
	defer s.Close()
	_, err = s.Begin(context.Background())
	require.NoError(t, err)

	f.mu.Lock()
	defer f.mu.Unlock()
	require.Len(t, f.requests, 1)
	for _, request := range f.requests {
		require.Equal(t, "MCP credential access (3h idle, 18h max)", request.Label)
		require.LessOrEqual(t, len(request.Label), 80)
	}
}

func TestCloudSessionApprovalLabelFitsLimitAtFractionalBoundary(t *testing.T) {
	f := newBrowserFixture(t)
	longest := 30*24*time.Hour - time.Nanosecond
	s, err := NewCloudSessionWithPolicy(f.path, CloudSessionPolicy{
		IdleTimeout: longest,
		MaximumAge:  longest,
	})
	require.NoError(t, err)
	defer s.Close()
	_, err = s.Begin(context.Background())
	require.NoError(t, err)

	f.mu.Lock()
	defer f.mu.Unlock()
	require.Len(t, f.requests, 1)
	for _, request := range f.requests {
		require.Equal(t, "MCP credential access (719h59m59.999999999s idle, 719h59m59.999999999s max)", request.Label)
		require.Len(t, request.Label, 75)
		require.LessOrEqual(t, len(request.Label), 80)
	}
}
