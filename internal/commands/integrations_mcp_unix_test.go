//go:build !windows

package commands

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// fakeAppCLI installs a fake `claude` CLI whose MCP registrations live in a
// state file (one name per line) and returns that file's path.
func fakeAppCLI(t *testing.T, registered ...string) string {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, os.WriteFile(state, []byte(strings.Join(registered, "\n")+"\n"), 0600))
	script := `#!/bin/sh
state="` + state + `"
[ "$1" = mcp ] || exit 2
op="$2"; shift 2
case "$op" in
get) grep -qx "$1" "$state" && exit 0; echo "No MCP server found with name: $1"; exit 1 ;;
add) while [ "$1" != "--" ]; do name="$1"; shift; done; echo "$name" >> "$state" ;;
remove) for name; do :; done; grep -vx -e "$name" "$state" > "$state.new"; mv "$state.new" "$state" ;;
*) exit 2 ;;
esac
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return state
}

func registrations(t *testing.T, state string) []string {
	t.Helper()
	b, err := os.ReadFile(state)
	require.NoError(t, err)
	return strings.Fields(string(b))
}

func runRegister(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	require.NoError(t, registerMCP(cmd, t.TempDir(), "claude"))
	return out.String()
}

func TestRegisterMCPAddsHopkit(t *testing.T) {
	state := fakeAppCLI(t)
	runRegister(t)
	require.Equal(t, []string{"hopkit"}, registrations(t, state))
}

func TestRegisterMCPReplacesLegacySSHMRegistration(t *testing.T) {
	state := fakeAppCLI(t, "sshm", "other")
	out := runRegister(t)
	require.ElementsMatch(t, []string{"other", "hopkit"}, registrations(t, state))
	require.Contains(t, out, "legacy sshm MCP removed")
}

func TestRegisterMCPKeepsExistingHopkitAndDropsLegacy(t *testing.T) {
	state := fakeAppCLI(t, "hopkit", "sshm")
	runRegister(t)
	require.Equal(t, []string{"hopkit"}, registrations(t, state))
}
