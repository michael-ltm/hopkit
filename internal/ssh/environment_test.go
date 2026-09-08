package ssh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUserShellDetection(t *testing.T) {
	for _, shell := range []string{"/bin/bash", "/bin/zsh", "/usr/local/bin/bash", "/bin/sh"} {
		require.Equal(t, shell, userShell("banner\nSSHM_SHELL="+shell+"\n"))
	}
	for _, out := range []string{"SSHM_SHELL=/bin/fish", "SSHM_SHELL=$SHELL", "SSHM_SHELL=", "SSHM_SHELL=C:\\Windows\\cmd.exe", "Microsoft Windows [Version]", "SSHM_SHELL=/bin/sh;touch /tmp/x"} {
		require.Empty(t, userShell(out))
	}
}

func TestUserPathAddsMissingToolsWithoutOverridingSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	require.NoError(t, os.MkdirAll(bin, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "sshm-environment-test-tool"), []byte("#!/bin/sh\nprintf 'discovered\\n'\n"), 0700))
	primary := filepath.Join(home, "chosen bin")
	require.NoError(t, os.MkdirAll(primary, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(primary, "sshm-environment-test-tool"), []byte("#!/bin/sh\nprintf 'selected\\n'\n"), 0700))
	for _, tc := range []struct{ path, want string }{{"/usr/bin:/bin", "discovered\n"}, {primary + ":/usr/bin:/bin", "selected\n"}} {
		cmd := exec.Command("/bin/sh", "-c", userPathPrefix+userPathPrefix+"sshm-environment-test-tool")
		cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+tc.path)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		require.Equal(t, tc.want, string(out))
	}
}

func TestLoginCommandPreservesQuotedMultilineAndExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	for _, shell := range []string{"/bin/sh", "/bin/bash", "/bin/zsh"} {
		if _, err := os.Stat(shell); err != nil {
			continue
		}
		t.Run(shell, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			script := "cat <<'SSHM_END'\na'b $HOME `uname` \\\"quoted\\\"\nSSHM_END\nexit 17"
			out, err := exec.CommandContext(ctx, "/bin/sh", "-c", loginUserCommand(shell, script)).Output()
			var ee *exec.ExitError
			require.ErrorAs(t, err, &ee)
			require.Equal(t, 17, ee.ExitCode())
			require.Contains(t, string(out), "a'b $HOME `uname` \\\"quoted\\\"\n")
		})
	}
}

func TestEnvironmentReportNeverInfersLogoutOrAcceptsTokenAsIdentity(t *testing.T) {
	r := parseEnvironmentReport("github\tunavailable_in_session\naccount\tmichael-ltm\ntoken\tsecret\ntool_node\t/a b/node\n", "remote_ssh", "posix")
	require.Equal(t, "unavailable_in_session", r.GitHub)
	require.Empty(t, r.Account)
	require.Equal(t, "/a b/node", r.Tools["node"])
	r = parseEnvironmentReport("github\tverified\naccount\tmichael-ltm\n", "remote_ssh", "posix")
	require.Equal(t, "michael-ltm", r.Account)
	r = parseEnvironmentReport("github\tverified\naccount\tgho_secret\n", "remote_ssh", "posix")
	require.Empty(t, r.Account)
	r = parseEnvironmentReport("github\tnot_logged_in\n", "remote_ssh", "posix")
	require.Equal(t, "unknown", r.GitHub)
}

func TestWindowsEnvironmentNativeCommandExecution(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows shell test")
	}
	for _, tc := range []struct {
		name, command, want string
		cmd                 bool
		exit                int
	}{
		{"cmd", "echo sshm windows & exit /b 19", "sshm windows", true, 19},
		{"powershell", "Write-Output 'sshm a''b $HOME'; exit 23", "sshm a'b $HOME", false, 23},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := strings.Fields(windowsUserCommand(tc.command, tc.cmd))
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
			var ee *exec.ExitError
			require.ErrorAs(t, err, &ee, string(out))
			require.Equal(t, tc.exit, ee.ExitCode(), string(out))
			require.Contains(t, string(out), tc.want)
		})
	}
}

func TestWindowsEnvironmentReportScriptParsesNatively(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows shell test")
	}
	// Make gh unavailable to avoid using CI credentials or making network calls.
	script := windowsPathPrefix + "\n$env:Path=$env:SystemRoot+'\\System32'\n" + windowsEnvironmentCheck
	args := strings.Fields(encodeEnvironmentPowerShell(script))
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	require.NoError(t, err, string(out))
	r := parseEnvironmentReport(string(out), "local_process", "windows")
	require.Equal(t, "cli_not_found", r.GitHub, string(out))
	require.NotEmpty(t, r.User)
}

func TestWindowsEnvironmentPreservesSelectedToolInPathWithSpaces(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows PATH test")
	}
	dir := filepath.Join(t.TempDir(), "selected tools")
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sshm-env-test.cmd"), []byte("@echo selected-tool\r\n@exit /b 0\r\n"), 0600))
	args := strings.Fields(windowsUserCommand("sshm-env-test", true))
	cmd := exec.Command(args[0], args[1:]...)
	// Keep all standard Windows environment variables; change PATH only.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToLower(entry), "path=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+dir+";"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "selected-tool")
}

func TestDesktopDelegationIsOptInAndDoesNotReplay(t *testing.T) {
	script := desktopUserCommand("/bin/zsh", "printf 'user command'")
	require.Contains(t, script, "Library/Application Support/sshm/desktop/enabled")
	require.Contains(t, script, "exec sshm desktop exec --")
	// The exec invocation must replace the shell, including on error. No `||`
	// fallback may replay a write that was submitted before a transport failure.
	require.NotContains(t, script, "||")
}
