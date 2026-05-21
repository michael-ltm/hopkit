package safety

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskSecrets_RedactsIPv4(t *testing.T) {
	out := MaskSecrets("connecting to 203.0.113.42 now")
	require.Contains(t, out, "203.0.*.*")
	require.NotContains(t, out, "203.0.113.42")
}

func TestMaskSecrets_RedactsEnvAssignments(t *testing.T) {
	out := MaskSecrets("DB_PASS=hunter2\nAPI_KEY=abcdef123")
	require.Contains(t, out, "DB_PASS=***")
	require.Contains(t, out, "API_KEY=***")
	require.NotContains(t, out, "hunter2")
	require.NotContains(t, out, "abcdef123")
}

func TestMaskSecrets_RedactsPrivateKeyBlocks(t *testing.T) {
	in := "-----BEGIN OPENSSH PRIVATE KEY-----\nABCDEF\n-----END OPENSSH PRIVATE KEY-----"
	out := MaskSecrets(in)
	require.NotContains(t, out, "ABCDEF")
	require.Contains(t, out, "[redacted private key]")
}

func TestMaskSecrets_LeavesNormalTextAlone(t *testing.T) {
	in := "disk usage is 42% on /dev/sda1"
	require.Equal(t, in, MaskSecrets(in))
}
