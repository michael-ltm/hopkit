package pair

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildScripts_AreSingleLineAndSelfContained(t *testing.T) {
	scripts, err := BuildScripts("ssh-ed25519 AAAATEST pair@host", "http://100.64.0.1:4567/v1/pair/token", 22)
	require.NoError(t, err)
	require.NotContains(t, scripts.Windows, "\n")
	require.NotContains(t, scripts.POSIX, "\n")
	require.True(t, strings.HasPrefix(scripts.POSIX, "/bin/sh -c '"))
	require.Less(t, len(scripts.Windows), 8191, "Windows one-liner must fit the traditional cmd.exe command-length ceiling")
	require.Less(t, len(scripts.POSIX), 8191, "POSIX one-liner must stay below common console and clipboard truncation limits")
	require.Contains(t, scripts.Windows, "Compression.GzipStream")
	require.Contains(t, scripts.POSIX, "SSHM_PAIR_B64=")
	require.Contains(t, scripts.POSIX, "gzip -dc")
	require.Contains(t, scripts.POSIX, "/bin/sh -n")
	require.Contains(t, scripts.POSIX, "incomplete or corrupted")

	windows := decodeWindowsScript(t, scripts.Windows)
	require.Contains(t, windows, "Add-WindowsCapability")
	require.Contains(t, windows, "Get-AuthenticodeSignature")
	require.Contains(t, windows, "$cap=Add-WindowsCapability")
	require.Contains(t, windows, "if($cap.RestartNeeded)")
	require.Contains(t, windows, "requires a Windows restart")
	require.Contains(t, windows, "administrators_authorized_keys")
	require.Contains(t, windows, `"*${sid}:F"`)
	require.Contains(t, windows, "UseProxy=$false")
	require.NotContains(t, windows, "__PUBLIC_KEY_B64__")
	require.NotContains(t, windows, "__CALLBACK_URL__")

	posix := decodePOSIXScript(t, scripts.POSIX)
	require.Contains(t, posix, "openssh-server")
	require.Contains(t, posix, "systemsetup -setremotelogin on")
	require.Contains(t, posix, "authorized_keys")
	require.Contains(t, posix, "--noproxy '*'")
	require.NotContains(t, posix, "__PUBLIC_KEY_B64__")
	syntax := exec.Command("sh", "-n")
	syntax.Stdin = strings.NewReader(posix)
	require.NoError(t, syntax.Run())
	bootstrapSyntax := exec.Command("sh", "-n")
	bootstrapSyntax.Stdin = strings.NewReader(scripts.POSIX)
	require.NoError(t, bootstrapSyntax.Run(), "the copy-paste wrapper must itself be valid POSIX shell")
	if shellcheck, err := exec.LookPath("shellcheck"); err == nil {
		command := exec.Command(shellcheck, "--severity=warning", "-s", "sh", "-")
		command.Stdin = strings.NewReader(scripts.POSIX)
		output, checkErr := command.CombinedOutput()
		require.NoErrorf(t, checkErr, "shellcheck rejected the copy-paste wrapper: %s", output)
	}
}

func TestBuildScripts_StripsPublicKeyCommentsFromPayload(t *testing.T) {
	first, err := BuildScripts("ssh-ed25519 AAAATEST a-very-long-alias@sshm-pair", "http://100.64.0.1:4567/v1/pair/token", 22)
	require.NoError(t, err)
	second, err := BuildScripts("ssh-ed25519 AAAATEST another-comment", "http://100.64.0.1:4567/v1/pair/token", 22)
	require.NoError(t, err)
	require.Equal(t, first, second, "public-key comments are not authentication material and must not inflate one-liners")
}

func TestBuildPOSIXOneLiner_ExecutesOnlyAfterIntegrityAndSyntaxChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the generated command targets POSIX systems")
	}
	root := t.TempDir()
	temporaryFiles := filepath.Join(root, "temporary-files")
	require.NoError(t, os.Mkdir(temporaryFiles, 0o700))
	marker := filepath.Join(root, "executed")
	oneLiner, err := buildPOSIXOneLiner(`printf ok >"$SSHM_TEST_MARKER"`)
	require.NoError(t, err)

	command := exec.Command("sh", "-c", oneLiner)
	command.Env = append(os.Environ(), "SSHM_TEST_MARKER="+marker, "TMPDIR="+temporaryFiles)
	output, err := command.CombinedOutput()
	require.NoErrorf(t, err, "valid wrapper failed: %s", output)
	require.FileExists(t, marker)
	contents, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "ok", string(contents))
	entries, err := os.ReadDir(temporaryFiles)
	require.NoError(t, err)
	require.Empty(t, entries, "the wrapper must remove its private temporary directory")
}

func TestBuildPOSIXOneLiner_RejectsPayloadDamageBeforeExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the generated command targets POSIX systems")
	}
	oneLiner, err := buildPOSIXOneLiner(`printf corrupted >"$SSHM_TEST_MARKER"`)
	require.NoError(t, err)

	const payloadMarker = "SSHM_PAIR_B64="
	start := strings.Index(oneLiner, payloadMarker)
	require.NotEqual(t, -1, start)
	start += len(payloadMarker)
	end := strings.Index(oneLiner[start:], ";") + start
	require.Greater(t, end, start+8)
	payload := oneLiner[start:end]
	damageCases := map[string]func(string) string{
		"middle deletion like the reported clipboard failure": func(value string) string {
			middle := len(value) / 2
			return value[:middle] + value[middle+2:]
		},
		"tail truncation": func(value string) string {
			return value[:len(value)-2]
		},
		"extra trailing data": func(value string) string {
			return value + "A"
		},
		"same-length replacement": func(value string) string {
			middle := len(value) / 2
			replacement := byte('A')
			if value[middle] == replacement {
				replacement = 'B'
			}
			return value[:middle] + string(replacement) + value[middle+1:]
		},
	}

	for name, damage := range damageCases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			temporaryFiles := filepath.Join(root, "temporary-files")
			require.NoError(t, os.Mkdir(temporaryFiles, 0o700))
			marker := filepath.Join(root, "must-not-exist")
			corrupted := oneLiner[:start] + damage(payload) + oneLiner[end:]

			command := exec.Command("sh", "-c", corrupted)
			command.Env = append(os.Environ(), "SSHM_TEST_MARKER="+marker, "TMPDIR="+temporaryFiles)
			output, err := command.CombinedOutput()
			require.Error(t, err)
			require.Contains(t, string(output), "incomplete or corrupted")
			require.NoFileExists(t, marker, "a damaged payload must never execute even partially")
			entries, readErr := os.ReadDir(temporaryFiles)
			require.NoError(t, readErr)
			require.Empty(t, entries, "failure must not leave decoded payload files behind")
		})
	}
}

func TestBuildScripts_WindowsFallbackIsPinnedAndFailClosed(t *testing.T) {
	scripts, err := BuildScripts("ssh-ed25519 AAAATEST pair@host", "http://100.64.0.1:4567/v1/pair/token", 22022)
	require.NoError(t, err)
	windows := decodeWindowsScript(t, scripts.Windows)

	require.Contains(t, windows, "$openSshVersion='10.0.0.0p2-Preview'")
	require.Contains(t, windows, "PowerShell/Win32-OpenSSH/releases/download/$openSshVersion/$asset")
	require.Contains(t, windows, "'OpenSSH-ARM64.zip'='698c6aec31c1dd0fb996206e8741f4531a97355686b5431ef347d531b07fcd42'")
	require.Contains(t, windows, "'OpenSSH-Win64.zip'='23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5'")
	require.Contains(t, windows, "'OpenSSH-Win32.zip'='c61d7fea20ddfe0fc50eb56210a66464557721120f7794ff9cc883b5ba526abd'")
	require.Contains(t, windows, "Get-FileHash -Algorithm SHA256")
	require.Contains(t, windows, "SSHM_OPENSSH_ZIP")
	require.Contains(t, windows, "-and [string]::IsNullOrWhiteSpace($offlineZip)")
	require.Contains(t, windows, "SSHM_OPENSSH_ZIP is set; skipping the online Windows Capability attempt")
	require.Contains(t, windows, "Invoke-WebRequest")
	require.Contains(t, windows, "curl.exe")
	require.Contains(t, windows, "'--max-time','120'")
	require.Contains(t, windows, "Start-BitsTransfer")
	require.Contains(t, windows, "RetryInterval=60;RetryTimeout=120")
	require.Contains(t, windows, "Parameters.ContainsKey('MaxDownloadTime')")
	require.Contains(t, windows, "$bitsArgs['MaxDownloadTime']=180")
	require.Contains(t, windows, "Last error: $last")
	require.Contains(t, windows, "$client.Timeout=[TimeSpan]::FromSeconds(15)")
	require.Contains(t, windows, "Pair callback confirmation")
	require.NotContains(t, windows, "attempt $attempt:")
	require.Contains(t, windows, "pinned Microsoft Win32-OpenSSH Preview")
	require.NotContains(t, windows, "releases/latest")
	require.NotContains(t, windows, "api.github.com")
	require.NotContains(t, windows, "Invoke-RestMethod")
	require.NotContains(t, windows, "browser_download_url")
}

func TestBuildScripts_ValidatesWindowsIdentityAndRequestedPort(t *testing.T) {
	scripts, err := BuildScripts("ssh-ed25519 AAAATEST pair@host", "http://100.64.0.1:4567/v1/pair/token", 22022)
	require.NoError(t, err)
	windows := decodeWindowsScript(t, scripts.Windows)

	require.Contains(t, windows, "$sshPort=22022")
	require.Contains(t, windows, "$identityName=$identity.Name")
	require.Contains(t, windows, "$reportedUser=$identityName")
	require.Contains(t, windows, "$identityAuthority -ieq $env:COMPUTERNAME")
	require.Contains(t, windows, "$reportedUser=$env:USERNAME")
	require.Contains(t, windows, "$form['user']=$reportedUser")
	require.Contains(t, windows, "Microsoft Entra/AzureAD identities are not supported")
	require.Contains(t, windows, "Service/system identity")
	require.NotContains(t, windows, "$form['user']=$env:USERNAME")
	imagePathIndex := strings.Index(windows, "Services\\sshd' -Name ImagePath")
	parsedPathIndex := strings.Index(windows, "sshd service ImagePath could not be parsed")
	require.NotEqual(t, -1, imagePathIndex)
	require.NotEqual(t, -1, parsedPathIndex)
	require.Less(t, imagePathIndex, parsedPathIndex, "the service ImagePath must be read before it is parsed")
	require.Contains(t, windows, "$sshdServiceImagePath -match '(?:^|\\s)-f\\s+")
	require.Contains(t, windows, "$sshdConfig=$serviceConfig")
	require.Contains(t, windows, "$sshdExe -t -f $candidate")
	require.Contains(t, windows, "$sshdExe -t @configArgs")
	require.Contains(t, windows, "$sshdExe -T @configArgs")
	require.Contains(t, windows, "sshd service ImagePath could not be parsed")
	require.Contains(t, windows, "sshd service ImagePath points to a missing executable")
	require.NotContains(t, windows, "$candidates=@(")
	require.Contains(t, windows, `SSHM-OpenSSH-In-TCP-$sshPort`)
	require.Contains(t, windows, "Get-NetTCPConnection -State Listen -LocalPort $port")
}

func TestBuildScripts_WindowsServiceStartIsStateAwareAndRepairable(t *testing.T) {
	scripts, err := BuildScripts("ssh-ed25519 AAAATEST pair@host", "http://100.64.0.1:4567/v1/pair/token", 22)
	require.NoError(t, err)
	windows := decodeWindowsScript(t, scripts.Windows)

	require.NotContains(t, windows, "Restart-Service sshd")
	require.Contains(t, windows, "$serviceWasRunning=$service.Status -eq 'Running'")
	require.Contains(t, windows, "if(-not $serviceWasRunning){")
	require.Contains(t, windows, "Repair-SshdPermissions")
	require.Contains(t, windows, "FixHostFilePermissions.ps1")
	require.Contains(t, windows, "& $fix -Confirm:$false")
	require.Contains(t, windows, "Start-Service sshd -ErrorAction Stop")
	require.Contains(t, windows, "ServiceSpecificExitCode")
	require.Contains(t, windows, "OpenSSH/Operational")
	require.Contains(t, windows, "Service Control Manager")
	require.Contains(t, windows, "libcrypto.dll")
	require.Contains(t, windows, "System32\\libcrypto.dll")
	require.Contains(t, windows, "*S-1-5-18:(OI)(CI)F")
	require.Contains(t, windows, "*S-1-5-32-544:(OI)(CI)F")
	require.Contains(t, windows, "*S-1-5-11:(OI)(CI)RX")
	require.Contains(t, windows, "ssh_host_*_key")

	startIndex := strings.Index(windows, "Start-Service sshd -ErrorAction Stop")
	repairIndex := strings.Index(windows, "Repair-SshdPermissions")
	userDirIndex := strings.LastIndex(windows, "New-Item -ItemType Directory -Path $userSsh")
	keyIndex := strings.Index(windows, "Add-PublicKey $userKeys")
	firewallIndex := strings.Index(windows, "$firewallRule=")
	listenerIndex := strings.Index(windows, "if(-not $listening)")
	require.NotEqual(t, -1, startIndex)
	require.NotEqual(t, -1, repairIndex)
	require.NotEqual(t, -1, userDirIndex)
	require.NotEqual(t, -1, keyIndex)
	require.NotEqual(t, -1, firewallIndex)
	require.NotEqual(t, -1, listenerIndex)
	require.Less(t, startIndex, listenerIndex)
	require.Less(t, repairIndex, startIndex)
	require.Less(t, listenerIndex, userDirIndex, "the user key directory must not be mutated until sshd is listening")
	require.Less(t, listenerIndex, keyIndex, "the key must not be installed until sshd is running and listening")
	require.Less(t, keyIndex, firewallIndex, "the firewall rule is the final local mutation before callback")
}

func TestBuildScripts_WindowsSyntaxWhenPowerShellIsAvailable(t *testing.T) {
	shells := make([]string, 0, 2)
	seen := map[string]bool{}
	for _, name := range []string{"powershell.exe", "pwsh"} {
		shell, err := exec.LookPath(name)
		if err == nil && !seen[shell] {
			shells = append(shells, shell)
			seen[shell] = true
		}
	}
	if len(shells) == 0 {
		t.Skip("PowerShell is not installed on this test host")
	}
	scripts, err := BuildScripts("ssh-ed25519 AAAATEST pair@host", "http://100.64.0.1:4567/v1/pair/token", 22022)
	require.NoError(t, err)
	windows := decodeWindowsScript(t, scripts.Windows)
	for _, shell := range shells {
		t.Run(filepath.Base(shell), func(t *testing.T) {
			command := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command", "$source=[Console]::In.ReadToEnd();[void][ScriptBlock]::Create($source)")
			command.Stdin = strings.NewReader(windows)
			output, err := command.CombinedOutput()
			require.NoErrorf(t, err, "%s parser rejected generated script: %s", shell, output)
		})
	}
}

func TestBuildScripts_POSIXHasPortAndCallbackFallbacks(t *testing.T) {
	scripts, err := BuildScripts("ssh-ed25519 AAAATEST pair@host", "http://100.64.0.1:4567/v1/pair/token", 22022)
	require.NoError(t, err)
	posix := decodePOSIXScript(t, scripts.POSIX)

	require.Contains(t, posix, "SSH_PORT='22022'")
	require.Contains(t, posix, "pacman -S --needed --noconfirm")
	require.NotContains(t, posix, "pacman -Sy")
	require.Contains(t, posix, `"$SSHD" -t`)
	require.Contains(t, posix, `"$SSHD" -T`)
	require.Contains(t, posix, "SSH_CONFIG_CHANGED=1")
	require.Contains(t, posix, "systemctl restart sshd")
	require.Contains(t, posix, "Existing sshd effective configuration does not include requested Port")
	require.Contains(t, posix, "macOS includes an existing sshd even when Remote Login is off")
	require.Contains(t, posix, "port_is_listening")
	require.Contains(t, posix, "restorecon -RF")
	require.Contains(t, posix, "retry callback_curl")
	require.Contains(t, posix, "retry callback_wget")
	require.Contains(t, posix, "--connect-timeout 5 --max-time 15")
	require.Contains(t, posix, "CALLBACK_TOOL")
	require.Contains(t, posix, "callback_curl||true")
	require.Contains(t, posix, "NO_PROXY='*' no_proxy='*' wget")

	syntax := exec.Command("sh", "-n")
	syntax.Stdin = strings.NewReader(posix)
	require.NoError(t, syntax.Run())
}

func TestBuildScripts_RejectsInvalidInputs(t *testing.T) {
	_, err := BuildScripts("not-a-key", "http://100.64.0.1/x", 22)
	require.Error(t, err)
	_, err = BuildScripts("ssh-ed25519 AAAA", "https://public.example/x", 22)
	require.Error(t, err)
	_, err = BuildScripts("ssh-ed25519 AAAA", "http://100.64.0.1/x", 70000)
	require.Error(t, err)
}

func decodeWindowsScript(t *testing.T, oneLiner string) string {
	t.Helper()
	const marker = "$d='"
	start := strings.Index(oneLiner, marker)
	require.NotEqual(t, -1, start)
	start += len(marker)
	end := strings.Index(oneLiner[start:], "'") + start
	require.Greater(t, end, start)
	decoded, err := base64.StdEncoding.DecodeString(oneLiner[start:end])
	require.NoError(t, err)
	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	require.NoError(t, err)
	windowsBytes, err := io.ReadAll(gzipReader)
	require.NoError(t, err)
	require.NoError(t, gzipReader.Close())
	return string(windowsBytes)
}

func decodePOSIXScript(t *testing.T, oneLiner string) string {
	t.Helper()
	const marker = "SSHM_PAIR_B64="
	start := strings.Index(oneLiner, marker)
	require.NotEqual(t, -1, start)
	start += len(marker)
	end := strings.Index(oneLiner[start:], ";") + start
	require.Greater(t, end, start)
	decoded, err := base64.StdEncoding.DecodeString(oneLiner[start:end])
	require.NoError(t, err)
	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	require.NoError(t, err)
	posixBytes, err := io.ReadAll(gzipReader)
	require.NoError(t, err)
	require.NoError(t, gzipReader.Close())
	return string(posixBytes)
}
