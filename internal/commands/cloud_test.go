package commands

import (
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"testing"
)

func TestCloudPasswordVariantsRequireSelection(t *testing.T) {
	d := cloudsync.NewData()
	d.Credentials["credential_one"] = cloudsync.Credential{Kind: "password", Password: "synthetic-one"}
	d.Credentials["credential_two"] = cloudsync.Credential{Kind: "password", Password: "synthetic-two"}
	e := cloudsync.Entry{Server: config.Server{Auth: config.AuthPassword}, CredentialIDs: []string{"credential_one", "credential_two"}}
	_, _, _, err := cloudAuth(&cobra.Command{}, d, e, "")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "synthetic")
	_, _, p, err := cloudAuth(&cobra.Command{}, d, e, "credential_two")
	require.NoError(t, err)
	require.Equal(t, "synthetic-two", p)
	_, _, _, err = cloudAuth(&cobra.Command{}, d, e, "credential_other")
	require.Error(t, err)
}

func TestLoginSyncChoice(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  bool
	}{{"\n", true}, {"yes\n", true}, {"Y\n", true}, {"n\n", false}, {"no\n", false}, {"", false}, {"unexpected\n", false}} {
		c := &cobra.Command{}
		c.SetIn(strings.NewReader(tc.input))
		c.SetErr(io.Discard)
		got, err := askCloudSync(c)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
}
