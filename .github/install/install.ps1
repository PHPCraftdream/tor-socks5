# Установщик готовых бинарников tor-socks5 (latest stable release).
# Работает в Windows PowerShell 5.1 и PowerShell 7, Windows x86_64.
# Без прав администратора, без изменений PATH и конфигов.

[CmdletBinding()]
param(
    # Единственный переопределяемый параметр — каталог установки
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# PS 5.1: включить TLS 1.2 и парсинг без IE
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$RepoOwner = 'PHPCraftdream'
$RepoName = 'tor-socks5'
$BinName = 'tor-socks5.exe'

function Fail([string]$Message) {
    Write-Error "Ошибка: $Message" -ErrorAction Stop
}

function Test-IsWindowsHost {
    # PS 5.1 — только Windows; PS7 на Unix: предлагаем install.sh
    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        return $false
    }
    return $true
}

function Get-OsArch {
    # Учесть 32-битный процесс на 64-битной ОС
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    return $arch
}

function Resolve-InstallDir([string]$Requested) {
    if ($Requested) { return $Requested }
    $localAppData = $env:LOCALAPPDATA
    if (-not $localAppData) { Fail 'не найден LOCALAPPDATA; укажите -InstallDir' }
    return (Join-Path $localAppData 'Programs\tor-socks5')
}

function Get-LatestRelease {
    # Официальный API GitHub: latest stable (не draft, не prerelease).
    # -MaximumRedirection 0: api.github.com не редиректит; неожиданный 3xx — Fail.
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest" `
        -Method Get -TimeoutSec 60 -MaximumRedirection 0 -Headers @{ 'User-Agent' = "$RepoName-installer" }
    if (-not $release) { Fail 'пустой ответ GitHub API' }
    if ($release.draft) { Fail 'latest release помечен как draft' }
    if ($release.prerelease) { Fail 'latest release помечен как prerelease' }
    if (-not ([string]$release.tag_name)) { Fail 'пустой тег релиза' }
    return $release
}

function Test-SafeTag([string]$Tag) {
    # safe-tag: первый символ ASCII alnum, далее alnum/./_/-;
    # slash, percent-encoding, query/fragment исключены набором символов
    if ($Tag -notmatch '\A[A-Za-z0-9][A-Za-z0-9._-]*\z') {
        Fail "некорректный тег релиза: $Tag"
    }
}

# Выбор ассета ТОЧНЫМ равенством имени; archive и <archive>.sha256 — два отдельных ассета
function Select-ExactAssetUrl($Release, [string]$AssetName) {
    $found = @($Release.assets | Where-Object { [String]::Equals($_.name, $AssetName, [StringComparison]::Ordinal) })
    if ($found.Count -ne 1) {
        Fail "ожидался ровно один ассет '$AssetName', найдено: $($found.Count)"
    }
    return [string]$found[0].browser_download_url
}

function Assert-AssetDownloadUrl([string]$Url, [string]$Tag, [string]$AssetName) {
    if (-not $Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        Fail "URL ассета не HTTPS: $Url"
    }
    $u = [Uri]$Url
    if ($u.Scheme -ne 'https') {
        Fail "URL ассета не HTTPS: $Url"
    }
    if ($u.Host -ne 'github.com') {
        Fail "неожидаемый хост URL ассета: $($u.Host)"
    }
    # Канонический browser_download_url: без userinfo/query/fragment, порт 443 по умолчанию
    if ($u.UserInfo) { Fail "URL ассета содержит userinfo: $Url" }
    if ($u.Query -or $u.Fragment) { Fail "URL ассета содержит query/fragment: $Url" }
    if ($u.IsDefaultPort -eq $false) { Fail "URL ассета содержит нестандартный порт: $Url" }
    $expectedPath = "/$RepoOwner/$RepoName/releases/download/$Tag/$AssetName"
    if (-not [String]::Equals($u.AbsolutePath, $expectedPath, [StringComparison]::Ordinal)) {
        Fail "неожидаемый путь URL ассета: $($u.AbsolutePath)"
    }
}

function Get-LowercaseSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-ChecksumFile([string]$ChecksumPath, [string]$ArchiveName) {
    # Ровно ОДНА строка: 64 hex; РОВНО "  " (Unix) или " *" (Windows);
    # затем точное имя архива; опционально один финальный LF/CRLF.
    # Любая вторая строка (в т.ч. пустая) — reject: после одного
    # необязательного CRLF не должно оставаться текста.
    $raw = [System.IO.File]::ReadAllText($ChecksumPath)
    if ($raw -notmatch '\A([0-9a-fA-F]{64})(?:  | \*)([^\r\n]+)(?:\r?\n)?\z') {
        Fail 'не удалось разобрать checksum-файл (ожидается одна строка: hex + два пробела или " *" + имя)'
    }
    $hash = $Matches[1].ToLowerInvariant()
    $name = $Matches[2]
    if (-not [String]::Equals($name, $ArchiveName, [StringComparison]::Ordinal)) {
        Fail "неожидаемое имя файла в checksum: '$name'"
    }
    return $hash
}

function Expand-SingleEntry([string]$ZipPath, [System.IO.FileStream]$TargetStream) {
    # В zip должен быть РОВНО ОДИН entry TOTAL; имя — точное; regular-файл,
    # не каталог и не symlink/nonregular; payload непустой. Никаких путей из zip:
    # поток entry копируется в переданный извне FileStream (FileMode.CreateNew).
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = $null
    $entryStream = $null
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        if ($zip.Entries.Count -ne 1) {
            Fail "в архиве ожидается ровно один entry, найдено: $($zip.Entries.Count)"
        }
        $entry = $zip.Entries[0]
        if (-not [String]::Equals($entry.FullName, $BinName, [StringComparison]::Ordinal)) {
            Fail "в архиве неожидаемый файл: $($entry.FullName)"
        }
        if ($entry.Length -le 0) { Fail 'payload в архиве пуст' }
        # ZipArchiveEntry не имеет свойства Attributes; каталог определяется
        # DOS-флагом (ExternalAttributes & 0x10)
        $ext = [int]$entry.ExternalAttributes
        if (($ext -band 0x10) -ne 0) { Fail 'entry помечен как каталог (ExternalAttributes)' }
        $unixMode = ($ext -shr 16) -band 0xFFFF
        # Допустимы: 0 (Windows zip не объявляет unix-тип) и regular 0x8000.
        # Права без type-битов (например 0600) — это тоже regular, не symlink.
        $unixType = $unixMode -band 0xF000
        if ($unixMode -ne 0 -and $unixType -ne 0 -and $unixType -ne 0x8000) {
            Fail 'entry не является обычным файлом (unix-тип в ExternalAttributes)'
        }
        $entryStream = $entry.Open()
        $entryStream.CopyTo($TargetStream)
        $TargetStream.Flush()
    }
    finally {
        if ($entryStream) { $entryStream.Dispose() }
        if ($zip) { $zip.Dispose() }
    }
}

function Get-AssetWithHttpsRedirects {
    <#
        Скачивание с ручным bounded redirect (макс. 10 hop): Invoke-WebRequest
        с -MaximumRedirection 0; каждый 3xx проверяется — только HTTPS,
        без userinfo и нестандартного порта.
        Начальный URL валидирован вызывающим через Assert-AssetDownloadUrl;
        helper фиксирует его путь и для КАЖДОГО hop'а на github.com требует
        ТОЧНО этот путь. Разрешённые терминальные CDN-хосты GitHub:
        objects.githubusercontent.com и release-assets.githubusercontent.com
        (только HTTPS; signed URL несёт подпись в query — query у CDN не
        проверяется и путь CDN не ограничивается). Любой другой хост или
        изменённый github.com-путь — Fail. Целостность содержимого
        гарантирует SHA256-проверка.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile
    )
    $current = [Uri]$Uri
    $headers = @{ 'User-Agent' = "$RepoName-installer" }
    $allowedCdnHosts = @('objects.githubusercontent.com', 'release-assets.githubusercontent.com')
    $expectedPath = $current.AbsolutePath
    for ($hop = 0; ; $hop++) {
        if ($hop -gt 10) { Fail 'слишком много перенаправлений (>10)' }
        if ($current.Scheme -ne 'https') { Fail "перенаправление в не-HTTPS запрещено: $current" }
        if ($current.UserInfo) { Fail "перенаправление с userinfo запрещено: $current" }
        if (-not $current.IsDefaultPort) { Fail "перенаправление на нестандартный порт запрещено: $current" }
        if ($current.Host -eq 'github.com') {
            if (-not [String]::Equals($current.AbsolutePath, $expectedPath, [StringComparison]::Ordinal)) {
                Fail "неожидаемый путь download URL: $($current.AbsolutePath)"
            }
        }
        elseif ($allowedCdnHosts -cnotcontains $current.Host) {
            Fail "неожидаемый хост перенаправления: $($current.Host)"
        }
        try {
            Invoke-WebRequest -Uri $current -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 600 `
                -Headers $headers -OutFile $OutFile | Out-Null
            break   # 2xx: файл записан
        }
        catch {
            # Достаём Response из цепочки исключений (PS5.1: WebException.HttpWebResponse;
            # PS7: HttpResponseException.HttpResponseMessage)
            $resp = $null
            $e = $_.Exception
            while ($e) {
                if ($e.PSObject.Properties['Response'] -and $e.Response) { $resp = $e.Response; break }
                $e = $e.InnerException
            }
            if (-not $resp) { Fail "сетевой сбой при скачивании: $($_.Exception.Message)" }
            $status = [int]$resp.StatusCode
            if ($status -lt 300 -or $status -ge 400) {
                Fail "неожидаемый HTTP-статус $status при скачивании $current"
            }
            $location = $null
            if ($resp.GetType().Name -eq 'HttpResponseMessage') {
                # PS7: HttpResponseMessage.Headers.Location — Uri
                $location = $resp.Headers.Location
            }
            else {
                # PS5.1: HttpWebResponse.Headers — WebHeaderCollection, string
                $location = $resp.Headers['Location']
            }
            if (-not $location) { Fail "редирект $status без Location: $current" }
            $current = [Uri][System.Uri]::new($current, [string]$location)
        }
    }
    if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf)) { Fail 'файл не был скачан' }
    if ((Get-Item -LiteralPath $OutFile).Length -le 0) { Fail 'скачанный файл пуст' }
}

# Сериализация транзакции установки и cleanup для каталога установки:
# named mutex, имя — от SHA256 нормализованного полного пути (lowercase,
# без trailing separator). Mutex, а не файл-лок: pre-existing чужой файл-лок
# по фиксированному имени пришлось бы переиспользовать или удалять, что
# небезопасно; mutex не оставляет файлов и принадлежит только процессу.
$script:InstallMutex = $null
function Enter-InstallMutex([string]$DirPath) {
    # Windows-пути case-insensitive; нормализуем и сравниваем канонично
    try {
        $full = [System.IO.Path]::GetFullPath($DirPath).TrimEnd('\', '/').ToLowerInvariant()
    }
    catch {
        Fail "некорректный каталог установки: $DirPath ($($_.Exception.Message))"
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($full))
    }
    finally { $sha.Dispose() }
    $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    $mutex = [System.Threading.Mutex]::new($false, "Global\tor-socks5-install-$hex")
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
        Fail "не удалось получить mutex установки: $($_.Exception.Message)"
    }
    if (-not $owned) {
        $mutex.Dispose()
        Fail 'другой экземпляр установщика уже работает с этим каталогом установки'
    }
    $script:InstallMutex = $mutex
}

function Exit-InstallMutex {
    if ($script:InstallMutex) {
        try { $script:InstallMutex.ReleaseMutex() }
        catch { Write-Warning "Не удалось освободить mutex установки: $($_.Exception.Message)" -WarningAction Continue }
        $script:InstallMutex.Dispose()
        $script:InstallMutex = $null
    }
}

function Invoke-OldBackupCleanup([string]$DirPath) {
    # Удаляем ТОЛЬКО наш reserved namespace: tor-socks5.exe.old.<32 lowercase hex>.
    # Никаких recursive scans — только top-level файлы каталога установки.
    $pattern = '\A' + [regex]::Escape("$BinName.old.") + '[0-9a-f]{32}\z'
    $files = $null
    try {
        $files = [System.IO.Directory]::EnumerateFiles($DirPath, "$BinName.old.*")
    }
    catch {
        Write-Host "Не удалось перечислить backup-копии в $DirPath ($($_.Exception.Message)) — пропускаю cleanup"
        return
    }
    foreach ($path in $files) {
        $leaf = [System.IO.Path]::GetFileName($path)
        if ($leaf -cnotmatch $pattern) { continue }
        # Только обычные файлы: каталоги, symlink/reparse points — не трогаем
        try {
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) { continue }
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        }
        catch { continue }
        # Атомарный OS-probe: эксклюзивный ReadWrite-доступ + DeleteOnClose.
        # Запущенный PE / занятый файл — Open не удастся; свободный файл
        # удаляется при Dispose без TOCTOU. ACL/readonly не меняем.
        $stream = $null
        try {
            $stream = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::DeleteOnClose)
        }
        catch {
            Write-Host "Backup недоступен для эксклюзивного удаления и оставлен: $leaf ($($_.Exception.Message))"
            continue
        }
        finally {
            if ($stream) { $stream.Dispose() }
        }
        Write-Host "Удалён старый backup: $leaf"
    }
}

function Main {
    if (-not (Test-IsWindowsHost)) {
        Fail 'Windows PowerShell на Unix не поддерживается; используйте install.sh'
    }
    $arch = Get-OsArch
    if ($arch -ne 'AMD64') {
        Fail "неподдерживаемая архитектура: $arch (поддерживается только Windows x86_64)"
    }

    $destDir = Resolve-InstallDir $InstallDir
    if ($destDir -eq '\' -or $destDir -eq '/') { Fail 'некорректный каталог установки' }

    $release = Get-LatestRelease
    $script:Tag = [string]$release.tag_name
    Test-SafeTag $script:Tag
    $script:ArchiveName = "tor-socks5-$script:Tag-x86_64-pc-windows-msvc.zip"

    # Свежий пустой temp-каталог; создаём БЕЗ -Force: коллизия = ошибка,
    # чужой каталог не переиспользуется и не удаляется в finally
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tor-socks5-" + [System.Guid]::NewGuid().ToString('N'))
    $tmpCreated = $false
    $candidate = $null
    $candidateCreated = $false
    $candidateStream = $null
    try {
        New-Item -ItemType Directory -Path $tmpDir | Out-Null
        $tmpCreated = $true

        $archivePath = Join-Path $tmpDir $script:ArchiveName
        $checksumPath = "$archivePath.sha256"

        $archiveUrl = Select-ExactAssetUrl $release $script:ArchiveName
        $checksumUrl = Select-ExactAssetUrl $release "$script:ArchiveName.sha256"
        Assert-AssetDownloadUrl $archiveUrl $script:Tag $script:ArchiveName
        Assert-AssetDownloadUrl $checksumUrl $script:Tag "$script:ArchiveName.sha256"

        try {
            Get-AssetWithHttpsRedirects -Uri $archiveUrl -OutFile $archivePath
            Get-AssetWithHttpsRedirects -Uri $checksumUrl -OutFile $checksumPath
        }
        catch {
            Fail "сетевой сбой при скачивании: $($_.Exception.Message)"
        }

        $expected = Test-ChecksumFile $checksumPath $script:ArchiveName
        $actual = Get-LowercaseSha256 $archivePath
        if ($actual -ne $expected) {
            Fail "SHA256 не совпадает (ожидалось $expected, получено $actual)"
        }

        if (Test-Path -LiteralPath $destDir -PathType Leaf) {
            Fail "путь установки существует и не является каталогом: $destDir"
        }
        if (-not (Test-Path -LiteralPath $destDir -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $destDir | Out-Null
            }
            catch {
                Fail "не удалось создать каталог установки: $destDir ($($_.Exception.Message))"
            }
        }
        if (-not (Test-Path -LiteralPath $destDir -PathType Container)) {
            Fail "каталог установки недоступен: $destDir"
        }

        $destPath = Join-Path $destDir $BinName
        # Reject: назначение — существующий каталог (в т.ч. symlink-to-directory)
        if (Test-Path -LiteralPath $destPath -PathType Container) {
            Fail "путь назначения является каталогом: $destPath"
        }

        # Staging-файл: FileMode.CreateNew — только СВОЙ свежий файл.
        # $candidateCreated ставится ТОЛЬКО после успешного Open: при коллизии
        # (existing файл) finally не удалит чужой pre-existing путь
        $candidate = Join-Path $destDir ("{0}.tmp-{1}" -f $BinName, [System.Guid]::NewGuid().ToString('N'))
        try {
            $candidateStream = [System.IO.File]::Open($candidate, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $candidateCreated = $true
        }
        catch {
            Fail "не удалось создать staging-файл: $candidate ($($_.Exception.Message))"
        }

        Expand-SingleEntry $archivePath $candidateStream
        $candidateStream.Dispose()
        $candidateStream = $null

        # Кандидат полностью проверен (SHA256 архива + безопасная распаковка)
        # и лежит на той же ФС. Транзакция: под mutex переименовываем старый exe в
        # уникальный backup, затем candidate на canonical. Работающий процесс
        # удерживает старый inode и продолжает работу; никакие процессы
        # не останавливаются и не запускаются.
        Enter-InstallMutex $destDir
        Invoke-OldBackupCleanup $destDir

        $backupPath = $null
        if (Test-Path -LiteralPath $destPath -PathType Leaf) {
            # Уникальное backup-имя В ТОМ ЖЕ каталоге; File.Move не перезаписывает
            # существующий файл — коллизия с чужим путём будет ошибкой, не затиранием
            $backupPath = Join-Path $destDir ("{0}.old.{1}" -f $BinName, [System.Guid]::NewGuid().ToString('N'))
            [System.IO.File]::Move($destPath, $backupPath)
        }
        try {
            [System.IO.File]::Move($candidate, $destPath)
        }
        catch {
            # Rollback: вернуть backup ТОЛЬКО если canonical отсутствует;
            # чужой/неизвестный файл на canonical никогда не затираем
            if ($backupPath -and -not (Test-Path -LiteralPath $destPath)) {
                try {
                    [System.IO.File]::Move($backupPath, $destPath)
                    $backupPath = $null
                }
                catch {
                    Fail "установка не завершена; backup-копия сохранена: $backupPath ($($_.Exception.Message))"
                }
            }
            elseif ($backupPath) {
                Fail "установка не завершена; backup-копия сохранена: $backupPath"
            }
            Fail "не удалось установить бинарник: $($_.Exception.Message)"
        }
        $candidateCreated = $false
        $candidate = $null

        # Успешная установка: свежий backup больше не нужен; если старый
        # процесс ещё работает — файл занят и останется до следующей установки
        if ($backupPath) { Invoke-OldBackupCleanup $destDir }
    }
    finally {
        Exit-InstallMutex
        if ($candidateStream) { $candidateStream.Dispose() }
        if ($candidateCreated -and $candidate -and (Test-Path -LiteralPath $candidate)) {
            Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        }
        if ($tmpCreated -and (Test-Path -LiteralPath $tmpDir)) {
            Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Установлено: $destPath (релиз $script:Tag)"
    Write-Host "Запуск: $destPath"
    Write-Host 'Если каталог не в PATH — запускайте по полному пути.'
}

Main
