<#
.SYNOPSIS
Тестовая фикстура: захватывает named mutex установщика и держит его.

.DESCRIPTION
Имя мьютекса ДОЛЖНО точно совпадать с Enter-InstallMutex в install.ps1:
Global\tor-socks5-install-<SHA256(fullpath.TrimEnd('\','/').ToLowerInvariant(), UTF8)>.
При захвате печатает "READY" и блокируется на stdin до "exit"/EOF.
Только для тестов CI; запускается с известным PID, никаких kill.
#>
param(
    [Parameter(Mandatory = $true)][string]$InstallDir
)

$ErrorActionPreference = 'Stop'

$full = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\', '/').ToLowerInvariant()
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($full))
}
finally { $sha.Dispose() }
$hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
$name = "Global\tor-socks5-install-$hex"

$mutex = [System.Threading.Mutex]::new($false, $name)
$owned = $false
try {
    try {
        $owned = $mutex.WaitOne(0)
    }
    catch [System.Threading.AbandonedMutexException] {
        # Предыдущий владелец умер без Release — mutex ПРИОБРЕТЁН
        $owned = $true
    }
}
catch {
    $mutex.Dispose()
    throw "не удалось получить mutex установки: $($_.Exception.Message)"
}

if (-not $owned) {
    $mutex.Dispose()
    throw "mutex уже занят другим процессом: $name"
}

try {
    [Console]::Out.Write("READY`n")
    [Console]::Out.Flush()
    while ($true) {
        $line = [Console]::ReadLine()
        if ($null -eq $line) { break } # EOF
        if ($line -eq 'exit') { break }
    }
}
finally {
    try { $mutex.ReleaseMutex() }
    finally { $mutex.Dispose() }
}
