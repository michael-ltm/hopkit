package commands

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	cleanupmodel "github.com/michael-ltm/sshm/internal/cleanup"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/keystore"
	"github.com/michael-ltm/sshm/internal/pair"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestPairCandidate_NewAliasDoesNotRequireKnownUser(t *testing.T) {
	server, err := pairCandidate(nil, false, pairOptions{
		host: "100.64.0.1", port: 22, description: "Windows test PC", tags: "windows,test",
	})
	require.NoError(t, err)
	require.Empty(t, server.User)
	require.Equal(t, "100.64.0.1", server.Host)
	require.Equal(t, []string{"windows", "test"}, server.Tags)
}

func TestPairCandidate_ExistingAliasRefusesImplicitConnectionChange(t *testing.T) {
	existing := &config.Server{Host: "old.example", Port: 22, User: "old"}
	_, err := pairCandidate(existing, true, pairOptions{host: "new.example", hostSet: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sshm edit")
}

func TestSameReportedUser_WindowsDomainPrefix(t *testing.T) {
	require.True(t, sameReportedUser(pair.Report{User: "Administrator", Platform: "windows"}, `AC1549\administrator`))
	require.False(t, sameReportedUser(pair.Report{User: "Administrator", Platform: "windows"}, `AC1549\other`))
	require.True(t, sameReportedUser(pair.Report{User: "ubuntu", Platform: "linux"}, "ubuntu"))
}

func TestPairTargetForGuidedPlatform(t *testing.T) {
	require.Equal(t, "windows", pairTargetForPlatform(config.PlatformWindows))
	require.Equal(t, "posix", pairTargetForPlatform(config.PlatformLinux))
	require.Equal(t, "posix", pairTargetForPlatform(config.PlatformMacOS))
	require.Equal(t, "all", pairTargetForPlatform(""))
}

func TestPairListenAddressMatchesCallbackFamily(t *testing.T) {
	require.Equal(t, "0.0.0.0:0", pairListenAddress("100.64.0.1", ""))
	require.Equal(t, "[::]:0", pairListenAddress("fd7a:115c:a1e0::1", ""))
	require.Equal(t, ":0", pairListenAddress("node.tailnet.test", ""))
	require.Equal(t, "127.0.0.1:4567", pairListenAddress("fd7a:115c:a1e0::1", "127.0.0.1:4567"))
}

func TestPairRetryInstructionIsExecutableForNewAndExistingAliases(t *testing.T) {
	require.Contains(t, pairRetryInstruction("new-pc", false, "", "~/.ssh/id_ed25519_new-pc"), "rerun plain `sshm pair`")
	require.Contains(t, pairRetryInstruction("office-pc", true, "", "~/.ssh/id_ed25519_office-pc"), "`sshm pair office-pc`")
	require.Contains(t, pairRetryInstruction("new-pc", false, "/keys/custom", "/keys/custom"), `kept key "/keys/custom"`)
}

func TestWaitForPairCallbackRetryReturnsWhenTargetConfirms(t *testing.T) {
	retries := make(chan struct{}, 1)
	retries <- struct{}{}
	started := time.Now()
	waitForPairCallbackRetry(t.Context(), retries, time.Minute)
	require.Less(t, time.Since(started), time.Second)
}

func TestPairWithoutAliasRequiresTerminal(t *testing.T) {
	cmd := newPairCmd()
	cmd.SetIn(bytes.NewBuffer(nil))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires a terminal")
}

func TestPairPersistentFlagsDoNotCountAsPairFlags(t *testing.T) {
	root := NewRoot()
	root.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "config.toml"), "pair"})
	root.SetIn(bytes.NewBuffer(nil))
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires a terminal")
	require.NotContains(t, err.Error(), "pair flags require an alias")
}

func TestPlatformFromPairReportUsesDetectedSystem(t *testing.T) {
	require.Equal(t, config.PlatformWindows, platformFromPairReport("windows"))
	require.Equal(t, config.PlatformLinux, platformFromPairReport("linux"))
	require.Equal(t, config.PlatformMacOS, platformFromPairReport("darwin"))
}

func TestServerManagerDimensions_DefaultAndOptionBound(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetErr(&bytes.Buffer{})
	width, height := serverManagerDimensions(cmd, 50)
	require.Equal(t, 94, width)
	require.Equal(t, 18, height)
	_, height = serverManagerDimensions(cmd, 3)
	require.Equal(t, 3, height)
}

func TestInitialServerChoicePreservesOnlyExistingAlias(t *testing.T) {
	aliases := []string{"alpha", "office-pc", "zeta"}
	require.Equal(t, "office-pc", initialServerChoice(aliases, "office-pc"))
	require.Equal(t, "alpha", initialServerChoice(aliases, "removed-server"))
	require.Equal(t, "alpha", initialServerChoice(aliases, ""))
	require.Equal(t, managerAdd, initialServerChoice(nil, "office-pc"))
}

func TestServerChoiceLabel_NeverWrapsConfiguredWidth(t *testing.T) {
	server := &config.Server{
		Host: "very-long-windows-hostname.tailnet.example", User: "Administrator",
		Description: "这是一段很长的中文服务器说明，用来验证窄终端不会把一个选项折成很多行导致滚动遗漏",
	}
	for _, width := range []int{20, 31, 40, 60, 94, 140} {
		label := serverChoiceLabel("a-very-long-server-alias", server, width)
		require.NotContains(t, label, "\n")
		require.LessOrEqual(t, lipgloss.Width(label), width)
	}
}

func TestCleanupChoiceLabelNeverWrapsConfiguredWidth(t *testing.T) {
	entry := cleanupmodel.Entry{
		Alias:       "a-very-long-server-alias",
		Platform:    config.PlatformWindows,
		Reason:      cleanupmodel.ReasonIdle,
		IdleDays:    180,
		Description: "这是一段很长的中文服务器说明，用来验证清理选择器在窄终端也不会换行溢出",
	}
	for _, width := range []int{20, 31, 40, 60, 94} {
		label := cleanupChoiceLabel(entry, width)
		require.NotContains(t, label, "\n")
		require.LessOrEqual(t, lipgloss.Width(label), width)
	}
}

func TestWritePairCommandFiles_WritesPrivateSingleLineFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "commands")
	scripts, err := pair.BuildScripts(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7m3yZ9Qf0xV8u2nR4sP6cD1bH5jL7eT9wA2gM4 pair@host",
		"http://[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535/v1/pair/9f1b7c3d5e8a2046Qx7_pL2zN8vR4mT6wY0kC5hZ7Qa",
		22,
	)
	require.NoError(t, err)
	t.Logf("realistic generated command bytes: Windows=%d POSIX=%d", len(scripts.Windows), len(scripts.POSIX))
	require.Less(t, len(scripts.Windows), maxPrintedPairCommandBytes+1, "a realistic Windows command must remain printable without truncation")
	require.Less(t, len(scripts.POSIX), maxPrintedPairCommandBytes+1, "a realistic POSIX command must remain printable without truncation")
	require.Less(t, len(scripts.Windows), 8150, "keep headroom after a maximum-length IPv6 callback below the Windows console ceiling")
	paths, err := writePairCommandFiles(dir, "demo", "all", scripts)
	require.NoError(t, err)
	require.Len(t, paths, 2)
	expected := map[string]string{
		"demo.windows.ps1": scripts.Windows + "\n",
		"demo.posix.sh":    scripts.POSIX + "\n",
	}
	for _, path := range paths {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		if runtime.GOOS != "windows" {
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		require.Equal(t, expected[filepath.Base(path)], string(data), "command files must preserve the generated one-liner exactly")
		require.Equal(t, 1, bytes.Count(data, []byte("\n")))
	}
}

func TestValidatePrintedPairCommandLengthsGuardsClipboardOutputOnly(t *testing.T) {
	short := strings.Repeat("x", maxPrintedPairCommandBytes)
	tooLong := short + "x"
	require.NoError(t, validatePrintedPairCommandLengths("all", pair.Scripts{Windows: short, POSIX: short}))

	err := validatePrintedPairCommandLengths("posix", pair.Scripts{Windows: short, POSIX: tooLong})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Linux/macOS")
	require.Contains(t, err.Error(), "--script-dir")

	err = validatePrintedPairCommandLengths("windows", pair.Scripts{Windows: tooLong, POSIX: short})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Windows")
	require.Contains(t, err.Error(), "--script-dir")

	require.NoError(t, validatePrintedPairCommandLengths("windows", pair.Scripts{Windows: short, POSIX: tooLong}), "an unselected command must not block file/clipboard output")
}

func TestPreparePairKeyExistingKeyMustPassSigningPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	_, err := keys.GenerateED25519(path, "existing@test")
	require.NoError(t, err)

	originalCheck := checkPairKeyUsable
	t.Cleanup(func() { checkPairKeyUsable = originalCheck })
	checkPairKeyUsable = func(gotPath string) (string, error) {
		require.Equal(t, path, gotPath)
		return "", errors.New("agent refused signing")
	}

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	publicKey, generated, err := preparePairKey(cmd, "existing", path, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not ready for SSH signing")
	require.Contains(t, err.Error(), "ssh-add")
	require.Empty(t, publicKey)
	require.False(t, generated)
	require.FileExists(t, path, "an existing user-owned key must never be deleted on preflight failure")
	require.FileExists(t, path+".pub")
	require.Empty(t, out.String())
}

func TestPreparePairKeyExistingPlainKeyPassesRealSigningPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	_, err := keys.GenerateED25519(path, "existing@test")
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	publicKey, generated, err := preparePairKey(cmd, "existing", path, false)
	require.NoError(t, err)
	require.Contains(t, publicKey, "ssh-ed25519")
	require.False(t, generated)
}

func TestPreparePairKeyPublishesTheExactPublicKeyReturnedByPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	_, err := keys.GenerateED25519(path, "existing@test")
	require.NoError(t, err)

	originalCheck := checkPairKeyUsable
	t.Cleanup(func() { checkPairKeyUsable = originalCheck })
	const checkedPublicKey = "ssh-ed25519 checked-by-preflight"
	checkPairKeyUsable = func(string) (string, error) { return checkedPublicKey, nil }

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	publicKey, generated, err := preparePairKey(cmd, "existing", path, false)
	require.NoError(t, err)
	require.Equal(t, checkedPublicKey, publicKey)
	require.False(t, generated)
}

func TestPreparePairKeyEncryptedAgentLoadFailureIsFatalAndKeepsRecoveryForRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generated")
	originalStore := storeAndLoadPairKey
	originalCheck := checkPairKeyUsable
	t.Cleanup(func() {
		storeAndLoadPairKey = originalStore
		checkPairKeyUsable = originalCheck
	})

	storeCalled := false
	storeAndLoadPairKey = func(gotPath, passphrase string) (keystore.Result, error) {
		storeCalled = true
		require.Equal(t, path, gotPath)
		require.NotEmpty(t, passphrase)
		data, err := os.ReadFile(gotPath)
		require.NoError(t, err)
		_, err = gssh.ParsePrivateKey(data)
		var missing *gssh.PassphraseMissingError
		require.ErrorAs(t, err, &missing, "pair must remain encrypted by default")
		return keystore.Result{}, errors.New("agent unavailable")
	}
	checkPairKeyUsable = func(string) (string, error) {
		t.Fatal("signing preflight must not run when agent load already failed")
		return "", nil
	}

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	publicKey, generated, err := preparePairKey(cmd, "new", path, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "could not be loaded for SSH signing")
	require.Contains(t, err.Error(), "OpenSSH Authentication Agent")
	require.True(t, storeCalled)
	require.Empty(t, publicKey)
	require.False(t, generated)
	require.FileExists(t, path)
	require.FileExists(t, path+".pub")
	require.FileExists(t, path+".passphrase")
	require.Contains(t, err.Error(), strconv.Quote(path+".passphrase"))
	require.Empty(t, out.String(), "recovery instructions are printed only after the key is usable")
}

func TestPreparePairKeyEncryptedSigningPreflightFailureIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generated")
	originalStore := storeAndLoadPairKey
	originalCheck := checkPairKeyUsable
	t.Cleanup(func() {
		storeAndLoadPairKey = originalStore
		checkPairKeyUsable = originalCheck
	})
	storeAndLoadPairKey = func(string, string) (keystore.Result, error) {
		return keystore.Result{Persisted: true}, nil
	}
	checkPairKeyUsable = func(string) (string, error) { return "", errors.New("sign request rejected") }

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	publicKey, generated, err := preparePairKey(cmd, "new", path, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed its SSH signing preflight")
	require.Contains(t, err.Error(), "running and unlocked")
	require.Empty(t, publicKey)
	require.False(t, generated)
	require.FileExists(t, path)
	require.FileExists(t, path+".pub")
	require.FileExists(t, path+".passphrase")
	require.Contains(t, err.Error(), strconv.Quote(path+".passphrase"))
	require.Empty(t, out.String())
}

func TestPreparePairKeyPlainGenerationAlsoRequiresSigningPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generated")
	originalCheck := checkPairKeyUsable
	t.Cleanup(func() { checkPairKeyUsable = originalCheck })
	checkPairKeyUsable = func(string) (string, error) { return "", errors.New("signing broken") }

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	_, generated, err := preparePairKey(cmd, "new", path, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signing preflight")
	require.False(t, generated)
	require.NoFileExists(t, path)
	require.NoFileExists(t, path+".pub")
}

func TestRunPairCommandDoesNotPrintTargetCommandBeforeSigningPreflight(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	flagConfigPath = cfgPath
	originalCheck := checkPairKeyUsable
	t.Cleanup(func() {
		flagConfigPath = ""
		checkPairKeyUsable = originalCheck
	})
	checkPairKeyUsable = func(string) (string, error) {
		return "", errors.New("signing unavailable")
	}

	opts := defaultPairOptions()
	opts.host = "127.0.0.1"
	opts.callbackHost = "127.0.0.1"
	opts.listen = "127.0.0.1:0"
	opts.keyPath = filepath.Join(dir, "id_pair")
	opts.noEncrypt = true
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := runPairCommand(cmd, "new", opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signing preflight")
	require.Empty(t, out.String())
	require.NotContains(t, out.String(), "Windows (run in Administrator PowerShell)")
	require.NotContains(t, out.String(), "Linux/macOS")
}
