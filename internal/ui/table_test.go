package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestRenderServerTable_IncludesAllExpectedColumns(t *testing.T) {
	servers := map[string]*config.Server{
		"prod-web": {
			Host: "1.2.3.4", Port: 22, User: "ubuntu", Auth: config.AuthKey,
			Tags: []string{"prod", "web"}, LastStatus: config.StatusOnline,
			Description: "primary production web server",
			LastSeen:    time.Now().Add(-2 * time.Minute),
		},
		"staging": {
			Host: "1.2.3.5", Port: 22, User: "ubuntu", Auth: config.AuthKey,
			LastStatus: config.StatusOffline,
		},
	}
	out := RenderServerTable(servers, ASCIIIcons(), false /* no color */)

	for _, want := range []string{"ID", "STATUS", "DESCRIPTION", "HOST", "USER", "AUTH", "prod-web", "primary production web server", "staging", "[OK] on", "[X] off"} {
		require.Contains(t, out, want, "table missing %q", want)
	}
	// Aliases sorted alphabetically.
	require.Less(t, strings.Index(out, "prod-web"), strings.Index(out, "staging"))
}

func TestRenderServerTable_EmptyShowsHint(t *testing.T) {
	out := RenderServerTable(map[string]*config.Server{}, ASCIIIcons(), false)
	require.Contains(t, out, "No servers")
	require.Contains(t, out, "sshm add")
}
