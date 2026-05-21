package bootstrap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScript_IsEmbeddedAndNonEmpty(t *testing.T) {
	require.NotEmpty(t, Script())
	require.Contains(t, Script(), "SSHM-BOOTSTRAP-START")
	require.Contains(t, Script(), "SSHM-BOOTSTRAP-DONE")
}

func TestParseResult_DetectsCompletion(t *testing.T) {
	ok := ParseResult("=SSHM-BOOTSTRAP-START=\nfoo\n=SSHM-BOOTSTRAP-DONE=\n")
	require.True(t, ok.Completed)

	bad := ParseResult("=SSHM-BOOTSTRAP-START=\nhalfway")
	require.False(t, bad.Completed)
}

func TestParseResult_CapturesSshdState(t *testing.T) {
	raw := "=SSHM-BOOTSTRAP-START=\n=SSHD-STATE=\nPasswordAuthentication no\nPermitRootLogin no\n=SSHM-BOOTSTRAP-DONE=\n"
	r := ParseResult(raw)
	require.Contains(t, strings.Join(r.SSHDState, "\n"), "PasswordAuthentication no")
	require.Contains(t, strings.Join(r.SSHDState, "\n"), "PermitRootLogin no")
}
