package ssh

import (
	"errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestInstallationOutputDistinguishesMissingAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		out             string
		err             error
		status, version string
	}{{"SSHM_NOT_INSTALLED\n", nil, "missing", ""}, {"SSHM_INSTALLED\n0.8.0-cloud-preview.12\n", nil, "installed", "0.8.0-cloud-preview.12"}, {"SSHM_INSTALLED\nsshm v0.7.0\n", nil, "installed", "0.7.0"}, {"SSHM_INSTALLED\ncustom version", nil, "installed", ""}, {"", errors.New("timeout"), "unknown", ""}, {"permission denied", nil, "unknown", ""}} {
		status, version := installationOutput(tc.out, tc.err)
		require.Equal(t, tc.status, status)
		require.Equal(t, tc.version, version)
	}
}
