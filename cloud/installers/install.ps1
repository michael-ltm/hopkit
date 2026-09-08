# PowerShell 5.1+; user installation, no administrator or execution-policy changes.
& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  if ($env:OS -ne 'Windows_NT') { throw 'Use: curl -fsSL https://sshm.yunmini.net/install.sh | sh' }
  $machine = $env:PROCESSOR_ARCHITEW6432
  if (-not $machine) { $machine = $env:PROCESSOR_ARCHITECTURE }
  switch ($machine.ToUpperInvariant()) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "Unsupported Windows architecture: $machine. A 64-bit OS is required." }
  }
  $hashes = @{
@@WINDOWS_ASSETS@@
  }
  $version = '@@VERSION@@'
  $dir = $env:SSHM_INSTALL_DIR
  if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\sshm' }
  if (-not [IO.Path]::IsPathRooted($dir)) { throw 'SSHM_INSTALL_DIR must be an absolute path.' }
  [IO.Directory]::CreateDirectory($dir) | Out-Null
  $work = Join-Path $dir ('.install-' + [Guid]::NewGuid().ToString('N'))
  [IO.Directory]::CreateDirectory($work) | Out-Null
  $temp = Join-Path $work 'sshm.exe'
  $target = Join-Path $dir 'sshm.exe'
  $oldTls = [Net.ServicePointManager]::SecurityProtocol
  try {
    [Net.ServicePointManager]::SecurityProtocol = $oldTls -bor [Net.SecurityProtocolType]::Tls12
    Write-Output "Installing SSHM $version (windows/$arch)..."
    $url = "https://sshm.yunmini.net/downloads/sshm-windows-$arch.exe"
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
      & curl.exe --silent --show-error --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --retry 2 --output $temp $url
      if ($LASTEXITCODE -ne 0) { throw 'Download failed; check proxy, network and CA certificates, then retry.' }
    } else {
      Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $temp -TimeoutSec 180
    }
    if ((Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$arch]) { throw 'SHA-256 mismatch; existing installation retained. Download a fresh installer and retry.' }
    $observed = & $temp version
    if ($LASTEXITCODE -ne 0 -or $observed.Trim() -ne $version) { throw 'Client cannot run on this OS, or version is unexpected; existing installation retained.' }
    if (Test-Path -LiteralPath $target) {
      $backup = $target + '.backup-' + [Guid]::NewGuid().ToString('N')
      try { [IO.File]::Replace($temp, $target, $backup) }
      catch { throw "Cannot replace SSHM (it may be running). Close SSHM processes and retry. Existing installation retained. $($_.Exception.Message)" }
      Write-Output "Previous binary: $backup"
    } else { [IO.File]::Move($temp, $target) }
    if ($env:SSHM_NO_PATH -ne '1') {
      $userPath = [Environment]::GetEnvironmentVariable('Path','User')
      $parts = @($userPath -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ine $dir.TrimEnd('\') })
      [Environment]::SetEnvironmentVariable('Path', (@($dir) + $parts -join ';'), 'User')
      $env:Path = $dir + ';' + $env:Path
    }
    & $target cloud report-version --quiet | Out-Null
    Write-Output "Installed: $target"
    Write-Output 'Run sshm version. Open a new terminal if your app still uses its old PATH.'
    if ($env:SSHM_INSTALL_INTEGRATIONS -eq '1') { & $target integrations install --app all --mcp; if ($LASTEXITCODE -ne 0) { throw 'Client installed; AI integration needs attention.' } }
  } finally {
    [Net.ServicePointManager]::SecurityProtocol = $oldTls
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
  }
}
