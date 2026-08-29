//go:build windows

package keys

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func requireProtectedDACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	require.NoError(t, err)
	control, _, err := descriptor.Control()
	require.NoError(t, err)
	require.NotZero(t, control&windows.SE_DACL_PROTECTED, "%s must not inherit a broad parent DACL", path)
}

func TestPrivateArtifactsUseProtectedWindowsDACL(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_windows_acl")
	_, err := GenerateED25519Encrypted(keyPath, "acl@test", "secret")
	require.NoError(t, err)
	requireProtectedDACL(t, keyPath)

	recoveryPath, err := WriteRecovery(keyPath, "secret")
	require.NoError(t, err)
	requireProtectedDACL(t, recoveryPath)
}
