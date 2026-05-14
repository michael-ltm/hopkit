package keys

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildCopyIDCommand_EscapesKey(t *testing.T) {
	cmd := BuildCopyIDCommand("ssh-ed25519 AAA... test@h")
	// Should create ~/.ssh, append the key, dedupe, set perms.
	for _, want := range []string{"mkdir -p", "~/.ssh", "authorized_keys", "ssh-ed25519 AAA...", "chmod 700", "chmod 600", "awk"} {
		require.Contains(t, cmd, want, "missing %q in: %s", want, cmd)
	}
}

func TestBuildCopyIDCommand_RejectsEmpty(t *testing.T) {
	require.Panics(t, func() { BuildCopyIDCommand("") })
}

func TestBuildCopyIDCommand_RejectsNewlineInKey(t *testing.T) {
	require.Panics(t, func() {
		BuildCopyIDCommand("ssh-ed25519 AAA\nmalicious-command")
	})
}

func TestBuildCopyIDCommand_QuotesProperly(t *testing.T) {
	cmd := BuildCopyIDCommand("ssh-ed25519 AAA")
	// Single-quote the key inside heredoc-safe content
	require.NotContains(t, cmd, "''")
	require.True(t, strings.Contains(cmd, "<<'EOF'") || strings.Contains(cmd, `<<EOF`))
}

func TestBuildCopyIDCommand_MetacharactersNotExpanded(t *testing.T) {
	key := "ssh-ed25519 AAAA $HOME `id` user@h"
	cmd := BuildCopyIDCommand(key)
	// The key must appear verbatim — <<'EOF' prevents shell expansion.
	require.Contains(t, cmd, key)
	require.Contains(t, cmd, "<<'EOF'")
}
