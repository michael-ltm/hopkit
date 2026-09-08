//go:build darwin

package desktopsession

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func fakeGitHubCLI(t *testing.T, body string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(k, "")
	}
	dir, _ := markerDir()
	require.NoError(t, os.MkdirAll(dir, 0700))
	gh := filepath.Join(home, "native gh")
	require.NoError(t, os.WriteFile(gh, []byte("#!/bin/sh\n"+body), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gh-path"), []byte(gh), 0600))
}

func TestGitHubBridgeSuppliesOnlyChildCredential(t *testing.T) {
	fakeGitHubCLI(t, "if [ \"$GH_TOKEN\" = synthetic-credential ]; then printf delegated; else exit 8; fi\n")
	old := readDesktopGitHubCredential
	t.Cleanup(func() { readDesktopGitHubCredential = old })
	calls := 0
	readDesktopGitHubCredential = func(context.Context) ([]byte, error) { calls++; return []byte("synthetic-credential"), nil }
	var out bytes.Buffer
	code, err := RunGitHub(context.Background(), []string{"api", "user"}, strings.NewReader(""), &out, io.Discard)
	require.NoError(t, err)
	require.Zero(t, code)
	require.Equal(t, "delegated", out.String())
	require.Equal(t, 1, calls)
	require.Empty(t, os.Getenv("GH_TOKEN"), "parent environment must stay unchanged")
}

func TestGitHubBridgeRespectsExplicitCredentialAndMetadataCommands(t *testing.T) {
	fakeGitHubCLI(t, "printf executed\n")
	old := readDesktopGitHubCredential
	t.Cleanup(func() { readDesktopGitHubCredential = old })
	readDesktopGitHubCredential = func(context.Context) ([]byte, error) { t.Fatal("must not read desktop credentials"); return nil, nil }
	for _, args := range [][]string{{"--version"}, {"repo", "view", "--help"}, {"auth", "setup-git"}} {
		code, err := RunGitHub(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard)
		require.NoError(t, err)
		require.Zero(t, code)
	}
	t.Setenv("GH_TOKEN", "explicit-test-value")
	code, err := RunGitHub(context.Background(), []string{"api", "user"}, strings.NewReader(""), io.Discard, io.Discard)
	require.NoError(t, err)
	require.Zero(t, code)
}

func TestGitHubBridgeFailsBeforeCommandWhenCredentialUnavailable(t *testing.T) {
	fakeGitHubCLI(t, "printf must-not-run\n")
	old := readDesktopGitHubCredential
	t.Cleanup(func() { readDesktopGitHubCredential = old })
	readDesktopGitHubCredential = func(context.Context) ([]byte, error) { return nil, errors.New("unavailable") }
	var out bytes.Buffer
	code, err := RunGitHub(context.Background(), []string{"api", "user"}, strings.NewReader(""), &out, io.Discard)
	require.Error(t, err)
	require.Equal(t, -1, code)
	require.Empty(t, out.String())
}

func TestGitHubCredentialHelperBindsHostAndOperation(t *testing.T) {
	fakeGitHubCLI(t, "printf must-not-run\n")
	old := readDesktopGitHubCredential
	t.Cleanup(func() { readDesktopGitHubCredential = old })
	readDesktopGitHubCredential = func(context.Context) ([]byte, error) {
		t.Fatal("must not disclose GitHub credential to another host")
		return nil, nil
	}
	for _, tc := range []struct{ op, input string }{{"get", "protocol=https\nhost=example.net\n\n"}, {"get", "protocol=http\nhost=github.com\n\n"}, {"store", "protocol=https\nhost=github.com\n\n"}, {"erase", "protocol=https\nhost=github.com\n\n"}} {
		var out bytes.Buffer
		code, err := RunGitHub(context.Background(), []string{"auth", "git-credential", tc.op}, strings.NewReader(tc.input), &out, io.Discard)
		require.NoError(t, err)
		require.Zero(t, code)
		require.Empty(t, out.String())
	}
}
