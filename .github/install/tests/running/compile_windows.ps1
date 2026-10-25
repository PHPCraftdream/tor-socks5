<#
.SYNOPSIS
Компилирует фикстуру blocking_app.cs в console-exe через Add-Type (Windows).

.DESCRIPTION
Только компиляция: читает доверенный source, подставляет маркер версии,
вызывает Add-Type. Ничего не запускает, ничего не скачивает.
Вызывается из CI в отдельном child PowerShell-процессе на каждую компиляцию,
чтобы избежать кэша типов Add-Type в одном процессе.
#>
param(
    [Parameter(Mandatory = $true)][string]$SourcePath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$VersionMarker
)

$ErrorActionPreference = 'Stop'

if ($VersionMarker -notmatch '^[A-Za-z0-9._-]+$') {
    throw "VersionMarker должен состоять только из ASCII [A-Za-z0-9._-]: '$VersionMarker'"
}

if (Test-Path -LiteralPath $OutputPath) {
    throw "Файл вывода уже существует, чужой файл не перетираем: $OutputPath"
}

if (-not (Test-Path -LiteralPath $SourcePath)) {
    throw "Исходный файл не найден: $SourcePath"
}

$source = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $SourcePath).Path)
$marker = '__FIXTURE_VERSION__'
if (-not $source.Contains($marker)) {
    throw "Плейсхолдер $marker не найден в $SourcePath"
}
$source = $source.Replace($marker, $VersionMarker)

Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly $OutputPath -OutputType ConsoleApplication

if (-not (Test-Path -LiteralPath $OutputPath)) {
    throw "Компиляция не создала файл вывода: $OutputPath"
}

Write-Output "COMPILED:$OutputPath"
