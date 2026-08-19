# One-time setup: sdkmanager --install "ndk;27.2.12479018" "platform-tools"
#                cargo install cargo-ndk --locked
#                rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

param(
    [string]$NdkHome = $env:ANDROID_NDK_HOME,
    [ValidateSet('armeabi-v7a','arm64-v8a','x86','x86_64','all')][string]$Abi = 'all',
    [string]$Package = 'socks5-proxy',
    [switch]$Debug
)

$RepoRoot = $PSScriptRoot | Split-Path -Parent

if (-not $NdkHome) {
    if ($env:ANDROID_HOME) {
        $SdkRoot = $env:ANDROID_HOME
    } else {
        $SdkRoot = 'D:\system_artefact\android-sdk'
    }

    $NdkDir = Join-Path $SdkRoot 'ndk'
    if (-not (Test-Path $NdkDir)) {
        throw "NDK directory not found at $NdkDir"
    }

    $NdkVersions = Get-ChildItem $NdkDir -Directory | Sort-Object Name -Descending
    if ($NdkVersions.Count -eq 0) {
        throw "No NDK installation found in $NdkDir"
    }

    $NdkHome = $NdkVersions[0].FullName
}

$SdkRoot = Split-Path (Split-Path $NdkHome -Parent) -Parent

$env:ANDROID_NDK_HOME = $NdkHome
$env:ANDROID_HOME = $SdkRoot

$AbiList = @('armeabi-v7a','arm64-v8a','x86','x86_64')
if ($Abi -ne 'all') {
    $AbiList = @($Abi)
}

$Config = 'release'
if ($Debug) {
    $Config = 'debug'
}

$TripleMap = @{
    'arm64-v8a' = 'aarch64-linux-android'
    'armeabi-v7a' = 'armv7-linux-androideabi'
    'x86_64' = 'x86_64-linux-android'
    'x86' = 'i686-linux-android'
}

foreach ($a in $AbiList) {
    Write-Host "Building for ABI: $a"
    $CargoArgs = @('ndk', '-t', $a, 'build', '-p', $Package)
    if (-not $Debug) {
        $CargoArgs += '--release'
    }
    cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for ABI: $a"
    }
}

$TargetDir = $env:CARGO_TARGET_DIR
if (-not $TargetDir) {
    $TargetDir = Join-Path $RepoRoot 'target'
}

Write-Host ""
Write-Host "Binaries built:"
foreach ($a in $AbiList) {
    $Triple = $TripleMap[$a]
    $BinaryPath = Join-Path $TargetDir "$Triple\$Config\$Package"
    Write-Host "$a -> $BinaryPath"
}
