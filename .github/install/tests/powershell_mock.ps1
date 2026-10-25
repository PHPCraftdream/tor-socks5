# Wrapper для offline-тестов install.ps1 (не production-код).
#
# Запускается тестами в Windows PowerShell 5.1 (`powershell`) И PowerShell 7
# (`pwsh`). Wrapper ТОЛЬКО определяет mock Invoke-RestMethod / Invoke-WebRequest
# (и, в узких сценариях, Join-Path) в родительском scope, затем ПОЛНОСТЬЮ
# вызывает НАСТОЯЩИЙ install.ps1 через dot-source. Production-функции не
# переписываются: весь алгоритм (выбор ассета, redirects, checksum, zip,
# transaction/cleanup) исполняется реальным скриптом.
#
# Сценарий: JSON (env не используется, путь приходит в -ScenarioPath):
#   release        — объект GitHub API: tag_name/draft/prerelease/assets[]
#   fail_api       — true: Invoke-RestMethod бросает сетевой сбой
#   downloads      — {<полный URL>: {file: путь-с-байтами, redirects: [...]}}
#   redirects[]    — {status: 302, location: "<url>" | null,
#                     shape: "ps51" | "ps7"}; пустой массив = 2xx сразу
#   joinpath_mode  — none | collision | fail-backup | delete-candidate
#   joinpath_path  — (collision) заранее созданный чужой файл-коллизия
#   log            — путь JSONL-журнала фактических вызовов mock'ов

param(
    [Parameter(Mandatory = $true)][string]$ScenarioPath,
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    # Пустая строка = установить через LOCALAPPDATA по умолчанию
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# PS 5.1: сборка System.Net.Http может быть не загружена
try { $null = [System.Net.Http.HttpResponseMessage] }
catch { Add-Type -AssemblyName System.Net.Http }

$Scen = Get-Content -LiteralPath $ScenarioPath -Raw -Encoding UTF8 | ConvertFrom-Json
$LogPath = $Scen.log

function Write-MockLog {
    param([hashtable]$Entry)
    Add-Content -LiteralPath $LogPath `
        -Value ($Entry | ConvertTo-Json -Compress) -Encoding UTF8
}

function Invoke-RestMethod {
    param($Uri, $Method, $TimeoutSec, $MaximumRedirection, $Headers)
    Write-MockLog @{
        fn = 'Invoke-RestMethod'; uri = [string]$Uri
        maximumRedirection = $MaximumRedirection
    }
    if ($Scen.fail_api) {
        throw [System.Exception]::new('mock: сбой сети GitHub API')
    }
    # Возвращаем объект ровно той формы, что парсит install.ps1
    return $Scen.release
}

function New-RedirectException {
    param([object]$Hop)
    if ($Hop.shape -eq 'ps7') {
        # PS7-форма: настоящий HttpResponseMessage, Location в Headers
        $resp = [System.Net.Http.HttpResponseMessage]::new(
            [System.Net.HttpStatusCode]::Found)
        if ($Hop.location) {
            $resp.Headers.Location = [System.Uri]$Hop.location
        }
    }
    else {
        # PS5.1-форма: HttpWebResponse-подобный объект с Headers-индексатором
        $headers = @{ }
        if ($Hop.location) { $headers['Location'] = [string]$Hop.location }
        $resp = [pscustomobject]@{ StatusCode = [int]$Hop.status; Headers = $headers }
    }
    $inner = [System.Exception]::new('mock: 3xx redirect')
    $inner | Add-Member -NotePropertyName Response -NotePropertyValue $resp
    # Внешнее исключение БЕЗ Response: проверяет обход цепочки InnerException
    return [System.Exception]::new('mock: iwr wrapper', $inner)
}

function Invoke-WebRequest {
    param($Uri, $MaximumRedirection, [switch]$UseBasicParsing, $TimeoutSec,
          $Headers, $OutFile)
    $url = [string]$Uri
    Write-MockLog @{
        fn = 'Invoke-WebRequest'; uri = $url; outFile = [string]$OutFile
        maximumRedirection = $MaximumRedirection
    }
    $downloads = $Scen.downloads
    $plan = $null
    if ($downloads) {
        $plan = $downloads.PSObject.Properties[$url].Value
    }
    if (-not $plan) {
        throw [System.Exception]::new("mock: необработанный download URL: $url")
    }
    $chain = @($plan.redirects)
    if ($chain.Count -gt 0) {
        throw (New-RedirectException $chain[0])
    }
    [System.IO.File]::WriteAllBytes($OutFile,
        [System.IO.File]::ReadAllBytes($plan.file))
}

# Узкий mock Join-Path ТОЛЬКО для генерации `.tmp-`/`.old.` имён: все прочие
# вызовы делегируются настоящему cmdlet (module-qualified call).
$script:CandidatePath = $null
if ($Scen.joinpath_mode -and $Scen.joinpath_mode -ne 'none') {
    function Join-Path {
        param($Path, $ChildPath)
        if ($ChildPath -like 'tor-socks5.exe.tmp-*') {
            if ($Scen.joinpath_mode -eq 'collision') {
                return [string]$Scen.joinpath_path
            }
            if ($Scen.joinpath_mode -eq 'delete-candidate') {
                $script:CandidatePath =
                    Microsoft.PowerShell.Management\Join-Path @PSBoundParameters
                return $script:CandidatePath
            }
        }
        if ($ChildPath -like 'tor-socks5.exe.old.*') {
            if ($Scen.joinpath_mode -eq 'delete-candidate') {
                # Удаляем candidate НЕПОСРЕДСТВОМНО перед final move
                if ($script:CandidatePath -and
                    (Test-Path -LiteralPath $script:CandidatePath)) {
                    Remove-Item -LiteralPath $script:CandidatePath -Force
                }
            }
            if ($Scen.joinpath_mode -eq 'fail-backup') {
                # Путь в несуществующем подкаталоге: File.Move старого exe
                # в backup упадёт — реальная rollback-логика получает сбой
                return [System.IO.Path]::Combine(
                    [string]$Path, 'no-such-subdir-for-backup', [string]$ChildPath)
            }
        }
        Microsoft.PowerShell.Management\Join-Path @PSBoundParameters
    }
}

try {
    # НАСТОЯЩИЙ установщик, без копий и переопределений его функций
    . $ScriptPath -InstallDir $InstallDir
}
catch {
    Write-Output ("FAILED: " + $_.Exception.Message)
    exit 1
}
exit 0
