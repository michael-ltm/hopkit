package mcp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
)

func TestCloudSessionStartsLockedAndNeverFallsBack(t *testing.T) {
	s := NewCloudSession(filepath.Join(t.TempDir(), "config.toml"))
	defer s.Close()
	require.Equal(t, "locked", s.Status().State)
	target := &config.Server{Host: "example.invalid", User: "ops", Port: 22, Auth: config.AuthCloud, CloudEntry: "entry_one", CloudVault: "owner"}
	_, _, cleanup, err := s.Resolve(context.Background(), target, sshpkg.BuildOpts{})
	if cleanup != nil {
		cleanup()
	}
	require.ErrorContains(t, err, "cloud_unlock")
	_, err = s.Begin(context.Background())
	require.Error(t, err)
	require.Equal(t, "locked", s.Status().State)
}
