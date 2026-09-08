$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$s=@{status='partial';platform='windows';notes=@();disks=@()}
try {$o=Get-CimInstance Win32_OperatingSystem; $s.os=$o.Caption+' '+$o.Version; $s.arch=$o.OSArchitecture; $s.memory_total=[uint64]$o.TotalVisibleMemorySize*1024; $s.memory_available=[uint64]$o.FreePhysicalMemory*1024} catch {$s.notes+= 'os_unavailable'}
try {$c=@(Get-CimInstance Win32_Processor);$s.cpu=($c.Name | Select-Object -Unique)-join ' / ';$s.cores=[int](($c | Measure-Object NumberOfCores -Sum).Sum);$s.threads=[int](($c | Measure-Object NumberOfLogicalProcessors -Sum).Sum)} catch {$s.notes+='cpu_unavailable'}
try {foreach($d in @(Get-CimInstance Win32_DiskDrive)) {$s.disks+=@{id=$d.DeviceID;kind='disk';model=$d.Model;total=[uint64]$d.Size}}} catch {$s.notes+='disks_unavailable'}
try {foreach($p in @(Get-CimInstance Win32_DiskPartition)) {$s.disks+=@{id=$p.DeviceID;parent=('\\.\PHYSICALDRIVE'+$p.DiskIndex);kind='partition';total=[uint64]$p.Size}}} catch {$s.notes+='partitions_unavailable'}
try {foreach($v in @(Get-CimInstance Win32_Volume)) { $m=@();if($v.DriveLetter){$m+=($v.DriveLetter+'\')};$s.disks+=@{id=$v.DeviceID;kind='volume';filesystem=$v.FileSystem;mounts=$m;total=[uint64]$v.Capacity;free=[uint64]$v.FreeSpace}}} catch {$s.notes+='volumes_unavailable'}
$s | ConvertTo-Json -Depth 8 -Compress
