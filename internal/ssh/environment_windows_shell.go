package ssh

import "strings"

// Refresh PATH only, without importing other registry values (which may contain
// credentials). Existing process entries win. Expansion handles standard Windows
// variables; the registry and process belong to the authenticated remote user.
const windowsPathPrefix = `$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$sshmExecPaths = @($env:Path)
foreach ($sshmExecScope in @('User', 'Machine')) {
 $sshmExecValue = [Environment]::GetEnvironmentVariable('Path', $sshmExecScope)
 if ($sshmExecValue) { $sshmExecPaths += [Environment]::ExpandEnvironmentVariables($sshmExecValue) }
}
$sshmExecPaths += @((Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links'), (Join-Path $env:APPDATA 'npm'))
$sshmExecSeen = @{}
$sshmExecMerged = foreach ($sshmExecEntry in ($sshmExecPaths -join ';').Split(';')) {
 $sshmExecEntry = $sshmExecEntry.Trim().Trim('"')
 if ($sshmExecEntry -and -not $sshmExecSeen.ContainsKey($sshmExecEntry)) {
  $sshmExecSeen[$sshmExecEntry] = $true
  $sshmExecEntry
 }
}
$env:Path = $sshmExecMerged -join ';'
$ErrorActionPreference = 'Continue'
`

func windowsUserCommand(command string, cmdShell bool) string {
	quoted := "'" + strings.ReplaceAll(command, "'", "''") + "'"
	script := windowsPathPrefix + "$sshmExecCommand = " + quoted + "\n"
	if cmdShell {
		script += "& $env:ComSpec /d /s /c $sshmExecCommand\nexit $LASTEXITCODE\n"
	} else {
		script += "& ([ScriptBlock]::Create($sshmExecCommand))\nif (-not $?) { if ($LASTEXITCODE) { exit $LASTEXITCODE }; exit 1 }\n"
	}
	return encodeEnvironmentPowerShell(script)
}
