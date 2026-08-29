package pair

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"
)

// Scripts contains the two copy-pasteable target commands generated for a
// pairing session. Each command is a single physical line.
type Scripts struct {
	Windows string
	POSIX   string
}

// BuildScripts embeds the public key and one-time callback in self-contained
// target scripts. No external bootstrap script is downloaded.
func BuildScripts(publicKey, callbackURL string, port int) (Scripts, error) {
	publicKey = strings.TrimSpace(publicKey)
	if !strings.HasPrefix(publicKey, "ssh-") || strings.ContainsAny(publicKey, "\r\n") {
		return Scripts{}, fmt.Errorf("public key must be one OpenSSH line")
	}
	if !strings.HasPrefix(callbackURL, "http://") || strings.ContainsAny(callbackURL, "\r\n'") {
		return Scripts{}, fmt.Errorf("callback URL is invalid")
	}
	if port < 1 || port > 65535 {
		return Scripts{}, fmt.Errorf("port must be in 1..65535")
	}

	pub64 := base64.StdEncoding.EncodeToString([]byte(publicKey))
	winScript := strings.NewReplacer(
		"__PUBLIC_KEY_B64__", pub64,
		"__CALLBACK_URL__", callbackURL,
		"__SSH_PORT__", fmt.Sprintf("%d", port),
	).Replace(windowsScript)
	posixScript := strings.NewReplacer(
		"__PUBLIC_KEY_B64__", pub64,
		"__CALLBACK_URL__", callbackURL,
		"__SSH_PORT__", fmt.Sprintf("%d", port),
	).Replace(posixScript)

	compressedWindows, err := gzipBase64(winScript)
	if err != nil {
		return Scripts{}, err
	}
	posixPayload := base64.StdEncoding.EncodeToString([]byte(posixScript))
	posixBootstrap := "SSHM_PAIR_B64=" + posixPayload + "; case \"$(uname -s)\" in Darwin) printf %s \"$SSHM_PAIR_B64\" | base64 -D | sh ;; *) printf %s \"$SSHM_PAIR_B64\" | base64 -d | sh ;; esac"
	return Scripts{
		Windows: "$d='" + compressedWindows + "';$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($d));$g=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress);$r=New-Object IO.StreamReader($g);$s=$r.ReadToEnd();$r.Dispose();$g.Dispose();$m.Dispose();&([ScriptBlock]::Create($s))",
		POSIX:   "/bin/sh -c '" + posixBootstrap + "'",
	}, nil
}

func gzipBase64(script string) (string, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(script)); err != nil {
		return "", fmt.Errorf("compress Windows pair script: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("finish Windows pair script compression: %w", err)
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), nil
}

const windowsScript = `$ErrorActionPreference='Stop'
$pairUrl='__CALLBACK_URL__'
$publicKey=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PUBLIC_KEY_B64__')).Trim()
$sshPort=__SSH_PORT__
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$identityName=$identity.Name
if(-not $identity.User -or [string]::IsNullOrWhiteSpace($identityName)){throw 'Cannot determine a supported Windows login identity for SSH pairing'}
if($identityName -match '^AzureAD\\'){throw "Microsoft Entra/AzureAD identities are not supported by Windows OpenSSH. Run this command as a local or Active Directory account. Detected: $identityName"}
if($identityName -match '^(NT AUTHORITY|NT SERVICE|Window Manager|Font Driver Host)\\'){throw "Service/system identity $identityName cannot be used as an interactive SSH login. Run this command as the account that will connect over SSH."}
$reportedUser=$identityName
if($identityName -match '^([^\\]+)\\(.+)$'){$identityAuthority=$Matches[1];if($identityAuthority -ieq $env:COMPUTERNAME){$reportedUser=$env:USERNAME}}
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this command in Administrator PowerShell'}
function Get-SshdService { Get-Service -Name sshd -ErrorAction SilentlyContinue }
function Test-OpenSSHArchive([string]$path){return (Test-Path -LiteralPath $path -PathType Leaf) -and ((Get-Item -LiteralPath $path).Length -gt 1000000)}
function Download-OpenSSH([string]$url,[string]$out){
  $failures=New-Object 'System.Collections.Generic.List[string]'
  for($attempt=1;$attempt -le 3;$attempt++){
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    try {Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out -TimeoutSec 90;if(Test-OpenSSHArchive $out){return};throw 'downloaded file is unexpectedly small'}
    catch {$failures.Add("IWR attempt ${attempt}: $($_.Exception.Message)");if($attempt -lt 3){Start-Sleep -Seconds (2*$attempt)}}
  }
  if(Get-Command curl.exe -ErrorAction SilentlyContinue){
    for($attempt=1;$attempt -le 3;$attempt++){
      Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
      try {$curlArgs=@('--fail','--location','--silent','--show-error','--retry','2','--connect-timeout','15','--max-time','120');if($attempt -eq 2){$curlArgs+=@('--noproxy','*')};$curlArgs+=@($url,'-o',$out);& curl.exe @curlArgs;if($LASTEXITCODE -ne 0){throw "curl exit $LASTEXITCODE"};if(Test-OpenSSHArchive $out){return};throw 'downloaded file is unexpectedly small'}
      catch {$failures.Add("curl attempt ${attempt}: $($_.Exception.Message)");if($attempt -lt 3){Start-Sleep -Seconds (2*$attempt)}}
    }
  }
  if(Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue){
    for($attempt=1;$attempt -le 3;$attempt++){
      Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
      try {$bitsArgs=@{Source=$url;Destination=$out;RetryInterval=60;RetryTimeout=120;ErrorAction='Stop'};if((Get-Command Start-BitsTransfer).Parameters.ContainsKey('MaxDownloadTime')){$bitsArgs['MaxDownloadTime']=180};Start-BitsTransfer @bitsArgs;if(Test-OpenSSHArchive $out){return};throw 'downloaded file is unexpectedly small'}
      catch {$failures.Add("BITS attempt ${attempt}: $($_.Exception.Message)");if($attempt -lt 3){Start-Sleep -Seconds (2*$attempt)}}
    }
  }
  throw "Pinned OpenSSH download failed through Invoke-WebRequest, curl, and BITS. Set SSHM_OPENSSH_ZIP to the matching official ZIP for an offline retry. $($failures -join '; ')"
}
$openSshVersion='10.0.0.0p2-Preview'
$openSshSha256=@{
  'OpenSSH-ARM64.zip'='698c6aec31c1dd0fb996206e8741f4531a97355686b5431ef347d531b07fcd42'
  'OpenSSH-Win64.zip'='23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5'
  'OpenSSH-Win32.zip'='c61d7fea20ddfe0fc50eb56210a66464557721120f7794ff9cc883b5ba526abd'
}
$serviceWasPresent=[bool](Get-SshdService)
$offlineZip=[string]$env:SSHM_OPENSSH_ZIP
if(-not $serviceWasPresent -and [string]::IsNullOrWhiteSpace($offlineZip)){
  try {Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop|Out-Null}
  catch {Write-Warning "Windows Capability install failed: $($_.Exception.Message)"}
} elseif(-not $serviceWasPresent) {
  Write-Host 'SSHM_OPENSSH_ZIP is set; skipping the online Windows Capability attempt.'
}
if(-not (Get-SshdService)){
  Write-Warning "Using pinned Microsoft Win32-OpenSSH Preview $openSshVersion fallback, not a stable Windows capability build"
  [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
  $nativeArch=if($env:PROCESSOR_ARCHITEW6432){$env:PROCESSOR_ARCHITEW6432}else{$env:PROCESSOR_ARCHITECTURE}
  $asset=if($nativeArch -eq 'ARM64'){'OpenSSH-ARM64.zip'}elseif([Environment]::Is64BitOperatingSystem){'OpenSSH-Win64.zip'}else{'OpenSSH-Win32.zip'}
  $expectedDigest=$openSshSha256[$asset]
  if($expectedDigest -notmatch '^[0-9a-f]{64}$'){throw "No pinned SHA256 is compiled for $asset"}
  $downloadUrl="https://github.com/PowerShell/Win32-OpenSSH/releases/download/$openSshVersion/$asset"
  $work=Join-Path $env:TEMP ('sshm-pair-'+[Guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $work|Out-Null
  try {
    $zip=Join-Path $work $asset
    if(-not [string]::IsNullOrWhiteSpace($offlineZip)){if(-not (Test-Path -LiteralPath $offlineZip -PathType Leaf)){throw "SSHM_OPENSSH_ZIP does not name a file: $offlineZip"};Copy-Item -LiteralPath $offlineZip -Destination $zip -Force}else{Download-OpenSSH $downloadUrl $zip}
    $actualDigest=(Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    if($actualDigest -ne $expectedDigest){throw "OpenSSH ZIP SHA256 mismatch for pinned $openSshVersion $asset (expected $expectedDigest, got $actualDigest)"}
    $expanded=Join-Path $work 'expanded';Expand-Archive -LiteralPath $zip -DestinationPath $expanded -Force
    $sshd=Get-ChildItem -LiteralPath $expanded -Filter sshd.exe -Recurse|Select-Object -First 1
    if(-not $sshd){throw 'Downloaded OpenSSH package does not contain sshd.exe'}
    $signature=Get-AuthenticodeSignature -LiteralPath $sshd.FullName
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'Downloaded sshd.exe does not have a valid Microsoft signature'}
    $source=$sshd.Directory.FullName;$dest=Join-Path $env:ProgramFiles 'OpenSSH'
    if((Test-Path $dest) -and (Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue)){ $dest=Join-Path $env:ProgramFiles 'OpenSSH-sshm' }
    New-Item -ItemType Directory -Path $dest -Force|Out-Null;Copy-Item -Path (Join-Path $source '*') -Destination $dest -Recurse -Force
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dest 'install-sshd.ps1')
    if($LASTEXITCODE -ne 0 -or -not (Get-SshdService)){throw 'install-sshd.ps1 did not create the sshd service'}
  } finally {Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
}
$service=Get-SshdService;if(-not $service){throw 'OpenSSH Server installation did not create sshd'}
$freshInstall=-not $serviceWasPresent
$sshdServiceImagePath=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
$sshdServiceImagePath=[Environment]::ExpandEnvironmentVariables([string]$sshdServiceImagePath)
function Get-SshdExecutable {
  $imagePath=$sshdServiceImagePath
  if($imagePath -match '^\s*"([^"]+sshd\.exe)"'){if(Test-Path -LiteralPath $Matches[1] -PathType Leaf){return $Matches[1]}}
  if($imagePath -match '^\s*(.+?sshd\.exe)(?:\s|$)'){if(Test-Path -LiteralPath $Matches[1] -PathType Leaf){return $Matches[1]}}
  $candidates=@((Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'),(Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'),(Join-Path $env:ProgramFiles 'OpenSSH-sshm\sshd.exe'))
  foreach($candidate in $candidates){if(Test-Path -LiteralPath $candidate -PathType Leaf){return $candidate}}
  $command=Get-Command sshd.exe -ErrorAction SilentlyContinue;if($command -and (Test-Path -LiteralPath $command.Source -PathType Leaf)){return $command.Source}
  throw 'sshd service exists, but sshd.exe could not be located for configuration validation'
}
$sshdExe=Get-SshdExecutable
Set-Service -Name sshd -StartupType Automatic
$programDataSsh=Join-Path $env:ProgramData 'ssh';New-Item -ItemType Directory -Path $programDataSsh -Force|Out-Null
$sshKeygen=Join-Path (Split-Path -Parent $sshdExe) 'ssh-keygen.exe'
if(Test-Path -LiteralPath $sshKeygen -PathType Leaf){& $sshKeygen -A;if($LASTEXITCODE -ne 0){throw 'ssh-keygen -A failed to create Windows SSH host keys'}}
$sshdConfig=Join-Path $programDataSsh 'sshd_config'
if(-not $freshInstall){$serviceConfig='';if($sshdServiceImagePath -match '(?:^|\s)-f\s+"([^"]+)"'){$serviceConfig=$Matches[1]}elseif($sshdServiceImagePath -match '(?:^|\s)-f\s+(\S+)'){$serviceConfig=$Matches[1]};if($serviceConfig){$serviceConfig=[Environment]::ExpandEnvironmentVariables($serviceConfig);if(-not (Test-Path -LiteralPath $serviceConfig -PathType Leaf)){throw "sshd service references a missing config file: $serviceConfig"};$sshdConfig=$serviceConfig}}
if($freshInstall -and -not (Test-Path -LiteralPath $sshdConfig -PathType Leaf)){$defaultConfig=Join-Path (Split-Path -Parent $sshdExe) 'sshd_config_default';if(-not (Test-Path -LiteralPath $defaultConfig -PathType Leaf)){throw 'Fresh OpenSSH install has no sshd_config or sshd_config_default'};Copy-Item -LiteralPath $defaultConfig -Destination $sshdConfig}
if($freshInstall -and $sshPort -ne 22){
  $candidate=$sshdConfig+'.sshm-pair.tmp'
  try {$originalConfig=[IO.File]::ReadAllBytes($sshdConfig);$base=[IO.File]::ReadAllText($sshdConfig);$candidateText="Port $sshPort"+[Environment]::NewLine+$base;[IO.File]::WriteAllText($candidate,$candidateText,[Text.Encoding]::ASCII);$candidateTest=& $sshdExe -t -f $candidate 2>&1;if($LASTEXITCODE -ne 0){throw "Fresh sshd custom-port configuration failed sshd -t: $($candidateTest -join ' ')"};Move-Item -LiteralPath $candidate -Destination $sshdConfig -Force;$installedTest=& $sshdExe -t -f $sshdConfig 2>&1;if($LASTEXITCODE -ne 0){[IO.File]::WriteAllBytes($sshdConfig,$originalConfig);throw "Fresh sshd custom-port configuration failed at its final path and was rolled back: $($installedTest -join ' ')"}}
  finally {Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue}
}
$configArgs=@();if(Test-Path -LiteralPath $sshdConfig -PathType Leaf){$configArgs=@('-f',$sshdConfig)}
$syntaxOutput=& $sshdExe -t @configArgs 2>&1;$syntaxCode=$LASTEXITCODE
if($syntaxCode -ne 0){throw "sshd configuration validation failed: $($syntaxOutput -join ' ')"}
$effectiveOutput=& $sshdExe -T @configArgs 2>&1;$effectiveCode=$LASTEXITCODE
if($effectiveCode -ne 0){throw "sshd effective-configuration check failed: $($effectiveOutput -join ' ')"}
$effectivePorts=@($effectiveOutput|ForEach-Object{if([string]$_ -match '^\s*port\s+(\d+)\s*$'){[int]$Matches[1]}})
if($effectivePorts -notcontains $sshPort){$installKind=if($freshInstall){'Newly installed'}else{'Existing'};throw "$installKind sshd effective configuration does not include requested port $sshPort (found: $($effectivePorts -join ',')). Configure Port $sshPort, validate with sshd -t, then rerun this command."}
$userSsh=Join-Path $env:USERPROFILE '.ssh';New-Item -ItemType Directory -Path $userSsh -Force|Out-Null
$userKeys=Join-Path $userSsh 'authorized_keys';$adminKeys=Join-Path $programDataSsh 'administrators_authorized_keys'
function Add-PublicKey([string]$path){$existing=if(Test-Path $path){Get-Content -LiteralPath $path -ErrorAction Stop}else{@()};if($existing -notcontains $publicKey){Add-Content -LiteralPath $path -Value $publicKey -Encoding ascii};if(-not (Test-Path $path)){throw "Failed to create $path"}}
Add-PublicKey $userKeys;Add-PublicKey $adminKeys
$sid=$identity.User.Value
& icacls.exe $userSsh /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed to secure the user .ssh directory ACL'}
& icacls.exe $userKeys /inheritance:r /grant:r "*${sid}:F" '*S-1-5-18:F'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed to secure the user authorized_keys ACL'}
& icacls.exe $adminKeys /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed to secure administrators_authorized_keys ACL'}
$firewallRule="SSHM-OpenSSH-In-TCP-$sshPort";$firewallDisplay="SSHM OpenSSH Server (TCP $sshPort)"
if(Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue){Get-NetFirewallRule -Name $firewallRule -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue;New-NetFirewallRule -Name $firewallRule -DisplayName $firewallDisplay -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $sshPort|Out-Null}
else {$netshName="name=$firewallDisplay";& netsh.exe advfirewall firewall delete rule $netshName dir=in protocol=TCP localport=$sshPort|Out-Null;& netsh.exe advfirewall firewall add rule $netshName dir=in action=allow protocol=TCP localport=$sshPort|Out-Null;if($LASTEXITCODE -ne 0){throw "Failed to open Windows Firewall TCP port $sshPort"}}
Restart-Service sshd
if((Get-Service sshd).Status -ne 'Running'){throw 'sshd is not running'}
function Test-SshdListening([int]$port){if(Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue){$listener=Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue|Select-Object -First 1;return [bool]$listener};$pattern='^\s*TCP\s+\S+[:.]'+[regex]::Escape([string]$port)+'\s+\S+\s+LISTENING';$listener=& netstat.exe -ano -p tcp 2>$null|Select-String -Pattern $pattern|Select-Object -First 1;return [bool]$listener}
$listening=$false;for($attempt=1;$attempt -le 15 -and -not $listening;$attempt++){$listening=Test-SshdListening $sshPort;if(-not $listening){Start-Sleep -Seconds 1}}
if(-not $listening){throw "sshd is running but TCP port $sshPort is not listening"}
$form=New-Object 'System.Collections.Generic.Dictionary[string,string]';$form['user']=$reportedUser;$form['hostname']=$env:COMPUTERNAME;$form['platform']='windows'
$handler=New-Object Net.Http.HttpClientHandler;$handler.UseProxy=$false;$client=New-Object Net.Http.HttpClient($handler);$client.Timeout=[TimeSpan]::FromSeconds(15)
try {$sent=$false;for($attempt=1;$attempt -le 3 -and -not $sent;$attempt++){$content=New-Object Net.Http.FormUrlEncodedContent($form);$response=$null;try{$response=$client.PostAsync($pairUrl,$content).GetAwaiter().GetResult();if($response.IsSuccessStatusCode){$sent=$true}else{throw "HTTP $([int]$response.StatusCode)"}}catch{if($attempt -eq 3){throw "Pair callback failed: $_"};Start-Sleep -Seconds (2*$attempt)}finally{if($response){$response.Dispose()};$content.Dispose()}};$content=New-Object Net.Http.FormUrlEncodedContent($form);$response=$null;try{$response=$client.PostAsync($pairUrl,$content).GetAwaiter().GetResult();if(-not $response.IsSuccessStatusCode){Write-Warning "Pair callback confirmation returned HTTP $([int]$response.StatusCode)"}}catch{Write-Warning "Pair callback confirmation was not received: $($_.Exception.Message)"}finally{if($response){$response.Dispose()};$content.Dispose()}} finally {$client.Dispose();$handler.Dispose()}
Write-Host "SSHM pair report sent for $reportedUser@$env:COMPUTERNAME; waiting for controller verification."
`

const posixScript = `set -eu
PAIR_URL='__CALLBACK_URL__'
PUBLIC_KEY_B64='__PUBLIC_KEY_B64__'
SSH_PORT='__SSH_PORT__'
TARGET_USER="${SUDO_USER:-$(id -un)}"
PLATFORM="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')"
case "$PLATFORM" in darwin) PLATFORM=darwin ;; linux) PLATFORM=linux ;; freebsd) PLATFORM=freebsd ;; *) PLATFORM=other-posix ;; esac
if [ "$(id -u)" -eq 0 ]; then SUDO=''; elif command -v sudo >/dev/null 2>&1; then SUDO=sudo; else SUDO=unavailable; fi
run_root() { if [ "$SUDO" = unavailable ]; then echo 'This step needs root or sudo' >&2; return 126; elif [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi; }
retry() { n=0; until "$@"; do n=$((n+1)); [ "$n" -ge 3 ] && return 1; sleep $((n*2)); done; }
find_sshd() { command -v sshd 2>/dev/null || { [ -x /usr/sbin/sshd ] && echo /usr/sbin/sshd; } || { [ -x /usr/local/sbin/sshd ] && echo /usr/local/sbin/sshd; }; }
install_packages() {
  if command -v apt-get >/dev/null 2>&1; then retry run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server curl || { retry run_root apt-get update && retry run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server curl; }
  elif command -v dnf >/dev/null 2>&1; then retry run_root dnf install -y openssh-server curl
  elif command -v yum >/dev/null 2>&1; then retry run_root yum install -y openssh-server curl
  elif command -v apk >/dev/null 2>&1; then retry run_root apk add openssh-server curl
  elif command -v zypper >/dev/null 2>&1; then retry run_root zypper --non-interactive install openssh curl
  elif command -v pacman >/dev/null 2>&1; then retry run_root pacman -S --needed --noconfirm openssh curl
  else return 1; fi
}
SSHD="$(find_sshd || true)"
if [ -n "$SSHD" ]; then SSHD_WAS_PRESENT=1; else SSHD_WAS_PRESENT=0; fi
if [ -z "$SSHD" ]; then install_packages || true; SSHD="$(find_sshd || true)"; fi
if [ -z "$SSHD" ]; then echo 'OpenSSH Server is missing and package installation failed. Fix the package mirror/network, then rerun this same command.' >&2; exit 1; fi
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then install_packages || true; fi
if command -v ssh-keygen >/dev/null 2>&1; then run_root ssh-keygen -A >/dev/null 2>&1 || true; fi
if [ "$PLATFORM" = linux ] && [ -d /run ]; then run_root install -d -m 755 /run/sshd >/dev/null 2>&1 || true;fi
SSH_CONFIG_CHANGED=0
configure_fresh_port() {
  [ "$SSH_PORT" = 22 ] && return 0
  SSHD_CONFIG=/etc/ssh/sshd_config
  [ -f "$SSHD_CONFIG" ] || { echo 'Fresh OpenSSH install has no /etc/ssh/sshd_config' >&2; return 1; }
  DROPIN=/etc/ssh/sshd_config.d/99-sshm-pair-port.conf
  if [ -d /etc/ssh/sshd_config.d ] && run_root grep -Eq '^[[:space:]]*Include[[:space:]].*sshd_config[.]d/[*]' "$SSHD_CONFIG"; then
    if run_root test -e "$DROPIN"; then echo "$DROPIN already exists; refusing to overwrite it" >&2; return 1; fi
    PORT_TMP="$(mktemp)";printf 'Port %s\n' "$SSH_PORT" >"$PORT_TMP"
    run_root install -m 600 "$PORT_TMP" "$DROPIN";rm -f "$PORT_TMP"
    if ! run_root "$SSHD" -t; then run_root rm -f "$DROPIN";echo "Fresh sshd Port $SSH_PORT configuration failed sshd -t and was rolled back" >&2;return 1;fi
    SSH_CONFIG_CHANGED=1
  else
    PORT_TMP="$(mktemp)";PORT_BACKUP="$(mktemp)";run_root cat "$SSHD_CONFIG" >"$PORT_BACKUP";{ printf 'Port %s\n' "$SSH_PORT";cat "$PORT_BACKUP"; } >"$PORT_TMP"
    if ! run_root "$SSHD" -t -f "$PORT_TMP"; then rm -f "$PORT_TMP" "$PORT_BACKUP";echo "Fresh sshd Port $SSH_PORT configuration failed sshd -t" >&2;return 1;fi
    run_root cp "$PORT_TMP" "$SSHD_CONFIG"
    if ! run_root "$SSHD" -t;then run_root cp "$PORT_BACKUP" "$SSHD_CONFIG";rm -f "$PORT_TMP" "$PORT_BACKUP";echo "Fresh sshd Port $SSH_PORT configuration failed at its final path and was rolled back" >&2;return 1;fi
    rm -f "$PORT_TMP" "$PORT_BACKUP";SSH_CONFIG_CHANGED=1
  fi
}
if [ "$SSHD_WAS_PRESENT" -eq 0 ]; then configure_fresh_port; fi
validate_sshd() { "$SSHD" -t >/dev/null 2>&1 || run_root "$SSHD" -t >/dev/null 2>&1; }
read_sshd_effective() { "$SSHD" -T 2>/dev/null || run_root "$SSHD" -T 2>/dev/null; }
if ! validate_sshd; then echo 'sshd configuration failed sshd -t; fix the configuration, then rerun this command.' >&2;exit 1;fi
if ! SSHD_EFFECTIVE="$(read_sshd_effective)"; then echo 'Cannot read sshd effective configuration with sshd -T; rerun as root or with working sudo.' >&2;exit 1;fi
if ! printf '%s\n' "$SSHD_EFFECTIVE"|awk -v p="$SSH_PORT" '$1=="port"&&$2==p{found=1}END{exit !found}'; then
  if [ "$PLATFORM" = darwin ]; then echo "macOS includes an existing sshd even when Remote Login is off; this command will not rewrite it. Enable/configure Remote Login for Port $SSH_PORT, validate with sshd -t, then rerun." >&2
  elif [ "$SSHD_WAS_PRESENT" -eq 1 ]; then echo "Existing sshd effective configuration does not include requested Port $SSH_PORT. Configure that port, validate with sshd -t, then rerun this command." >&2
  else echo "Newly installed sshd effective configuration does not include requested Port $SSH_PORT" >&2;fi
  exit 1
fi
SSH_ACTIVE=0
if [ -n "${SSH_CONNECTION:-}" ]; then SSH_ACTIVE=1
elif [ "$PLATFORM" = darwin ] && launchctl print system/com.openssh.sshd >/dev/null 2>&1; then SSH_ACTIVE=1
elif command -v systemctl >/dev/null 2>&1 && { systemctl is-active --quiet sshd || systemctl is-active --quiet ssh; }; then SSH_ACTIVE=1
fi
if [ "$SSH_CONFIG_CHANGED" -eq 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then run_root systemctl enable sshd >/dev/null 2>&1 || run_root systemctl enable ssh >/dev/null 2>&1;run_root systemctl restart sshd >/dev/null 2>&1 || run_root systemctl restart ssh >/dev/null 2>&1
  elif command -v rc-service >/dev/null 2>&1; then run_root rc-update add sshd default >/dev/null 2>&1 || true;run_root rc-service sshd restart
  elif command -v service >/dev/null 2>&1; then run_root service ssh restart >/dev/null 2>&1 || run_root service sshd restart >/dev/null 2>&1
  else echo 'OpenSSH custom port is configured, but no supported service manager was found to restart sshd' >&2;exit 1;fi
elif [ "$SSH_ACTIVE" -ne 1 ]; then
  if [ "$PLATFORM" = darwin ]; then
    run_root systemsetup -setremotelogin on >/dev/null 2>&1 || run_root launchctl load -w /System/Library/LaunchDaemons/ssh.plist >/dev/null 2>&1
  else
    if command -v systemctl >/dev/null 2>&1; then run_root systemctl enable --now sshd >/dev/null 2>&1 || run_root systemctl enable --now ssh >/dev/null 2>&1
    elif command -v rc-service >/dev/null 2>&1; then run_root rc-update add sshd default >/dev/null 2>&1 || true; run_root rc-service sshd restart
    elif command -v service >/dev/null 2>&1; then run_root service ssh restart >/dev/null 2>&1 || run_root service sshd restart >/dev/null 2>&1
    else echo 'OpenSSH is installed but no supported service manager was found' >&2; exit 1; fi
  fi
fi
if command -v getent >/dev/null 2>&1; then TARGET_HOME="$(getent passwd "$TARGET_USER" | awk -F: '{print $6}')"; elif [ "$TARGET_USER" = "$(id -un)" ]; then TARGET_HOME="$HOME"; elif [ "$PLATFORM" = darwin ]; then TARGET_HOME="$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory | awk '{print $2}')"; else TARGET_HOME=''; fi
if [ -z "$TARGET_HOME" ] || [ ! -d "$TARGET_HOME" ]; then echo "Cannot determine home directory for $TARGET_USER" >&2; exit 1; fi
TMP_KEY="$(mktemp)"; trap 'rm -f "$TMP_KEY"' EXIT HUP INT TERM
if printf %s "$PUBLIC_KEY_B64" | base64 -d >"$TMP_KEY" 2>/dev/null; then :; else printf %s "$PUBLIC_KEY_B64" | base64 -D >"$TMP_KEY"; fi
[ "$(wc -c <"$TMP_KEY" | tr -d ' ')" -ge 80 ] || { echo 'Embedded public key is invalid' >&2; exit 1; }
AUTH_DIR="$TARGET_HOME/.ssh";AUTH_FILE="$AUTH_DIR/authorized_keys"
install_key() { sh -c 'u=$1; d=$2; f=$3; k=$4; install -d -m 700 "$d"; touch "$f"; chmod 600 "$f"; grep -qxF "$(cat "$k")" "$f" || { printf "\n" >>"$f"; cat "$k" >>"$f"; printf "\n" >>"$f"; }; [ "$(id -u)" -ne 0 ] || chown -R "$u" "$d"' sh "$TARGET_USER" "$AUTH_DIR" "$AUTH_FILE" "$TMP_KEY"; }
if [ "$(id -u)" -ne 0 ] && [ "$TARGET_USER" = "$(id -un)" ]; then install_key; else run_root sh -c 'u=$1; d=$2; f=$3; k=$4; install -d -m 700 "$d"; touch "$f"; chmod 600 "$f"; grep -qxF "$(cat "$k")" "$f" || { printf "\n" >>"$f"; cat "$k" >>"$f"; printf "\n" >>"$f"; }; chown -R "$u" "$d"' sh "$TARGET_USER" "$AUTH_DIR" "$AUTH_FILE" "$TMP_KEY"; fi
if command -v restorecon >/dev/null 2>&1; then restorecon -RF "$AUTH_DIR" >/dev/null 2>&1 || run_root restorecon -RF "$AUTH_DIR" >/dev/null 2>&1 || { echo "Failed to restore SELinux context on $AUTH_DIR" >&2;exit 1;};fi
if command -v ufw >/dev/null 2>&1 && run_root ufw status 2>/dev/null | grep -q '^Status: active'; then run_root ufw allow "$SSH_PORT/tcp" >/dev/null
elif command -v firewall-cmd >/dev/null 2>&1 && run_root firewall-cmd --state >/dev/null 2>&1; then if [ "$SSH_PORT" = 22 ]; then run_root firewall-cmd --permanent --add-service=ssh >/dev/null;else run_root firewall-cmd --permanent --add-port="$SSH_PORT/tcp" >/dev/null;fi;run_root firewall-cmd --reload >/dev/null;fi
port_is_listening() {
  if command -v ss >/dev/null 2>&1; then ss -ltn 2>/dev/null|awk -v p="$SSH_PORT" '$1=="LISTEN"&&$4~("[.:]"p"$"){found=1}END{exit !found}'
  elif command -v netstat >/dev/null 2>&1; then netstat -an 2>/dev/null|awk -v p="$SSH_PORT" 'toupper($0)~/LISTEN/{for(i=1;i<=NF;i++)if($i~("[.:]"p"$"))found=1}END{exit !found}'
  elif [ -n "${SSH_CONNECTION:-}" ]; then [ "$(printf '%s\n' "$SSH_CONNECTION"|awk '{print $4}')" = "$SSH_PORT" ]
  else return 2;fi
}
LISTENING=0;LISTEN_STATUS=1;n=0
while [ "$n" -lt 15 ]; do if port_is_listening; then LISTENING=1;break;else LISTEN_STATUS=$?;[ "$LISTEN_STATUS" -eq 2 ]&&break;fi;n=$((n+1));sleep 1;done
if [ "$LISTENING" -ne 1 ]; then if [ "$LISTEN_STATUS" -eq 2 ]; then echo "sshd is ready, but neither ss nor netstat is available to verify TCP port $SSH_PORT" >&2;else echo "sshd is not listening on requested TCP port $SSH_PORT" >&2;fi;exit 1;fi
HOST_NAME="$(hostname 2>/dev/null || uname -n)"
callback_curl() { curl --fail --silent --show-error --connect-timeout 5 --max-time 15 --noproxy '*' -X POST --data-urlencode "user=$TARGET_USER" --data-urlencode "hostname=$HOST_NAME" --data-urlencode "platform=$PLATFORM" "$PAIR_URL" >/dev/null; }
callback_wget() { NO_PROXY='*' no_proxy='*' wget -qO- -T 15 -t 1 --post-data="user=$TARGET_USER&hostname=$HOST_NAME&platform=$PLATFORM" "$PAIR_URL" >/dev/null; }
CALLBACK_SENT=0;CALLBACK_TOOL=''
if command -v curl >/dev/null 2>&1 && retry callback_curl; then CALLBACK_SENT=1;CALLBACK_TOOL=curl;fi
if [ "$CALLBACK_SENT" -ne 1 ] && command -v wget >/dev/null 2>&1; then case "$TARGET_USER$HOST_NAME" in *[!A-Za-z0-9._@\\-]*) echo 'Username or hostname contains characters unsupported by the wget callback fallback' >&2;exit 1;;esac;if retry callback_wget;then CALLBACK_SENT=1;CALLBACK_TOOL=wget;fi;fi
if [ "$CALLBACK_SENT" -ne 1 ]; then echo 'OpenSSH is ready, but the callback failed after curl/wget retries. Check the route to the controller and rerun this command.' >&2;exit 1;fi
case "$CALLBACK_TOOL" in curl) callback_curl||true;;wget) callback_wget||true;;esac
echo "SSHM pair report sent for $TARGET_USER@$HOST_NAME; waiting for controller verification."
`
