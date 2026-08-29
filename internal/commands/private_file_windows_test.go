//go:build windows

package commands

import (
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/pair"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestPairCommandFilesUseProtectedWindowsDACL(t *testing.T) {
	paths, err := writePairCommandFiles(
		filepath.Join(t.TempDir(), "commands"),
		"demo",
		"all",
		pair.Scripts{Windows: "$x='win'", POSIX: "echo posix"},
	)
	require.NoError(t, err)
	require.Len(t, paths, 2)
	for _, path := range paths {
		descriptor, descriptorErr := windows.GetNamedSecurityInfo(
			path,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION,
		)
		require.NoError(t, descriptorErr)
		control, _, controlErr := descriptor.Control()
		require.NoError(t, controlErr)
		require.NotZero(t, control&windows.SE_DACL_PROTECTED, "%s must not inherit a broad parent DACL", path)
	}
}
