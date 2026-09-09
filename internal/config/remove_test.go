package config

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckServerRemovalReportsSortedProxyJumpReferences(t *testing.T) {
	cfg := New()
	cfg.Servers["gateway"] = &Server{Host: "10.0.0.1"}
	cfg.Servers["zeta"] = &Server{Host: "10.0.0.2", ProxyJump: " gateway "}
	cfg.Servers["alpha"] = &Server{Host: "10.0.0.3", ProxyJump: "gateway"}
	cfg.Projects["a-project"] = &Project{Server: "gateway"}

	err := CheckServerRemoval(cfg, "gateway")
	require.Error(t, err)
	var removalErr *ServerRemovalError
	require.True(t, errors.As(err, &removalErr))
	require.False(t, removalErr.NotFound)
	require.Equal(t, []string{"alpha", "zeta"}, removalErr.ProxyJumpServers)
	require.Contains(t, err.Error(), "servers using it as ProxyJump: alpha, zeta")
}

func TestRemoveServerClearsProjectReferences(t *testing.T) {
	cfg := New()
	cfg.Servers["gateway"] = &Server{Host: "10.0.0.1"}
	cfg.Projects["a-project"] = &Project{Server: "gateway"}
	cfg.Projects["other"] = &Project{Server: "gateway2"}

	require.NoError(t, RemoveServer(cfg, "gateway"))
	require.NotContains(t, cfg.Servers, "gateway")
	require.Equal(t, "", cfg.Projects["a-project"].Server)
	require.Equal(t, "gateway2", cfg.Projects["other"].Server)
}

func TestRemoveServerRejectsReferencesWithoutMutatingConfig(t *testing.T) {
	cfg := New()
	cfg.Servers["gateway"] = &Server{Host: "10.0.0.1"}
	cfg.Servers["app"] = &Server{Host: "10.0.0.2", ProxyJump: "gateway"}
	cfg.Default = "gateway"

	require.Error(t, RemoveServer(cfg, "gateway"))
	require.Contains(t, cfg.Servers, "gateway")
	require.Equal(t, "gateway", cfg.Default)
}
