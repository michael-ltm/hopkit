package pair

import "strings"

// WindowsLauncher runs the neighboring script with the OS PowerShell, ignoring
// user profiles. The filename is supplied only after alias validation.
func WindowsLauncher(scriptName string) string {
	return strings.ReplaceAll(`@echo off
setlocal DisableDelayedExpansion
set "SSHM_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "SSHM_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%SSHM_PS%" (
  echo Windows PowerShell is missing. Repair Windows PowerShell 5.1 before pairing.
  pause
  exit /b 1
)
if /I "%~1"=="check" goto check
"%SSHM_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0__SCRIPT__"
set "SSHM_EXIT=%ERRORLEVEL%"
echo.
pause
exit /b %SSHM_EXIT%
:check
"%SSHM_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0__SCRIPT__" -CheckOnly
exit /b %ERRORLEVEL%
`, "__SCRIPT__", scriptName)
}

// The diagnostic path exits before the installation payload, key writes,
// firewall changes or callback. It does not dump configuration or credentials.
const windowsFileHeader = `param([switch]$CheckOnly)
$ErrorActionPreference='Stop'
$sshmStage='PowerShell environment'
try {
  if($PSVersionTable.PSVersion -lt [version]'5.1'){throw 'Windows PowerShell 5.1 or newer is required'}
  if($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage'){throw 'PowerShell is restricted by system policy. Ask the Windows administrator to permit this script.'}
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $admin=(New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Write-Host "PowerShell $($PSVersionTable.PSVersion); elevated=$admin; architecture=$env:PROCESSOR_ARCHITECTURE"
  if($CheckOnly){
    $svc=Get-Service sshd -ErrorAction SilentlyContinue
    if(-not $svc){Write-Host 'OpenSSH Server: not installed. Pairing will try the Windows feature, then the verified official ZIP.';exit 0}
    Write-Host "OpenSSH Server: $($svc.Status)"
    $image=[Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' -Name ImagePath).ImagePath)
    if($image -match '^\s*"([^"]+sshd\.exe)"(?:\s|$)'){$exe=$Matches[1]}elseif($image -match '^\s*(.+?sshd\.exe)(?:\s|$)'){$exe=$Matches[1]}else{throw 'sshd service executable path could not be parsed'}
    if(-not (Test-Path -LiteralPath $exe -PathType Leaf)){throw 'sshd service executable is missing; repair the OpenSSH installation'}
    Write-Host "OpenSSH executable: $exe"
    if(-not $admin){Write-Host 'Run check as administrator for configuration validation.';exit 0}
    $config=Join-Path $env:ProgramData 'ssh\sshd_config'
    if($image -match '(?:^|\s)-f\s+"([^"]+)"'){$config=$Matches[1]}elseif($image -match '(?:^|\s)-f\s+(\S+)'){$config=$Matches[1]}
    $config=[Environment]::ExpandEnvironmentVariables($config)
    $sshmStage='OpenSSH configuration check'
    $validation=& $exe -t -f $config 2>&1
    if($LASTEXITCODE -ne 0){throw "sshd -t failed: $($validation -join ' ')"}
    $effective=& $exe -T -f $config 2>&1
    if($LASTEXITCODE -ne 0){throw 'sshd -T failed'}
    $ports=@($effective | ForEach-Object {if([string]$_ -match '^port (\d+)$'){[int]$Matches[1]}})
    Write-Host "Configuration valid; SSH ports: $($ports -join ', ')"
    if(Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue){
      foreach($port in $ports){$listeners=@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue);Write-Host "TCP $port listening: $($listeners.Count -gt 0)"}
    }
    Write-Host 'Read-only check finished. No keys, services or firewall rules were changed.'
    exit 0
  }
  if(-not $admin){throw 'Right-click the .windows.cmd file and choose Run as administrator, using the Windows account you want to pair.'}
`

const windowsFileFooter = `
} catch {
  # Avoid PowerShell's default source-line dump, which can contain the callback.
  [Console]::Error.WriteLine("SSHM failed during ${sshmStage}: $($_.Exception.Message)")
  [Console]::Error.WriteLine('Fix the reported step and retry while the controller is waiting. If it has expired, start a new pairing session with the same alias and key.')
  exit 1
}
`

func windowsFileStages(script string) string {
	for _, stage := range []struct{ marker, name string }{
		{"$identity=[Security.Principal.WindowsIdentity]", "Windows login identity"},
		{"$serviceWasPresent=[bool]", "OpenSSH installation"},
		{"$service=Get-SshdService;if(-not $service)", "OpenSSH configuration"},
		{"$service=Get-SshdService;$serviceWasRunning", "OpenSSH service startup"},
		{"$userSsh=Join-Path", "Public key and permissions"},
		{"$firewallRule=", "Windows Firewall"},
		{"$handler=New-Object Net.Http.HttpClientHandler", "Controller callback"},
	} {
		script = strings.Replace(script, stage.marker, "$sshmStage='"+stage.name+"';Write-Host \"SSHM: $sshmStage\"\n"+stage.marker, 1)
	}
	return script
}
