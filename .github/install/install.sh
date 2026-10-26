#!/bin/sh
# Установщик готовых бинарников tor-socks5 (latest stable release).
# POSIX sh. Без sudo, без изменений PATH и конфигов.
set -eu

REPO_OWNER=PHPCraftdream
REPO_NAME=tor-socks5
BIN_NAME=tor-socks5

err() {
    printf 'Ошибка: %s\n' "$1" >&2
    exit 1
}

usage() {
    cat <<EOF
Установка tor-socks5 (latest stable release)

Использование: sh install.sh [--install-dir DIR]

По умолчанию бинарник ставится в \$HOME/.local/bin.
PATH и конфигурационные файлы не изменяются.
EOF
}

# Точка входа: проверка платформы ДО любого скачивания
detect_target() {
    uname_s=$(uname -s)
    uname_m=$(uname -m)

    case "$uname_s" in
        Linux) os=linux ;;
        Darwin) os=macos ;;
        *) err "неподдерживаемая ОС: $uname_s (поддерживаются Linux и macOS)" ;;
    esac

    case "$uname_m" in
        x86_64|amd64) arch=x86_64 ;;
        arm64|aarch64)
            if [ "$os" = macos ]; then
                arch=aarch64
            else
                err "Linux ARM не поддерживается (только x86_64 GNU/glibc)"
            fi
            ;;
        *)
            err "неподдерживаемая архитектура: $uname_m"
            ;;
    esac

    # macOS: надёжное определение нативного ARM под Rosetta
    if [ "$os" = macos ] && [ "$arch" = x86_64 ]; then
        if sysctl -n hw.optional.arm64 2>/dev/null | grep -qx 1; then
            arch=aarch64
        fi
    fi

    case "$os" in
        linux)
            # Linux-ассет только x86_64-unknown-linux-gnu (glibc)
            target=x86_64-unknown-linux-gnu
            ;;
        macos)
            if [ "$arch" = aarch64 ]; then
                target=aarch64-apple-darwin
            else
                target=x86_64-apple-darwin
            fi
            ;;
    esac
}

# Извлечение тега из финального URL redirect-цепочки /releases/latest.
# Принимается ТОЛЬКО URL вида https://github.com/<owner>/<repo>/releases/tag/<safe-tag>
latest_tag() {
    final_url=$(curl -fsSL --proto '=https' --proto-redir '=https' --max-time 60 -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO_OWNER/$REPO_NAME/releases/latest") \
        || err "не удалось получить latest release (сетевой сбой?)"
    tag_prefix="https://github.com/$REPO_OWNER/$REPO_NAME/releases/tag/"
    case $final_url in
        "$tag_prefix"*) tag=${final_url#"$tag_prefix"} ;;
        *) err "неожидаемый URL latest release: $final_url" ;;
    esac
    # safe-tag: первый символ ASCII alnum, далее alnum/./_/-;
    # /, %, ?, # (query/fragment/percent-encoding) не входят в набор — reject
    case $tag in
        ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*)
            err "некорректный тег релиза: $tag"
            ;;
    esac
}

# Строгий парсер checksum-файла: ровно ОДНА строка;
# 64 hex; затем РОВНО "  " (Unix) или " *" (Windows); затем точное имя архива;
# опционально один финальный LF или CRLF. Любая вторая строка (в т.ч. пустая) — reject.
expected_hash() {
    sumfile=$1
    want_name=$2
    # Последний байт файла: CR допустим ТОЛЬКО как часть CRLF.
    # od -An -tu1 по последнему байту (command substitution нельзя —
    # она съедает trailing LF)
    last_byte=$(tail -c 1 "$sumfile" | od -An -tu1 | tr -d ' \t\n') || err "не удалось прочитать checksum-файл"
    if [ "$last_byte" = 13 ]; then
        err "checksum-файл оканчивается голым CR (без LF)"
    fi
    rc=0
    EXPECTED_SUM=$(awk -v want="$want_name" '
        {
            if (NR > 1) exit 10
            hex = substr($0, 1, 64)
            sep = substr($0, 65, 2)
            name = substr($0, 67)
        }
        END {
            if (NR != 1) exit 10
            if (length(hex) != 64 || hex ~ /[^0-9a-fA-F]/) exit 11
            if (sep != "  " && sep != " *") exit 12
            sub(/\r$/, "", name)   # один финальный CR от CRLF
            if (name != want) exit 13
            print tolower(hex)
        }
    ' "$sumfile") || rc=$?
    case $rc in
        0) ;;
        10) err "checksum-файл должен содержать ровно одну строку" ;;
        11) err "некорректная SHA256-сумма в checksum-файле" ;;
        12) err "не удалось разобрать checksum-файл (ожидается hex + два пробела или ' *' + имя)" ;;
        13) err "неожидаемое имя файла в checksum" ;;
        *) err "не удалось разобрать checksum-файл" ;;
    esac
}

# SHA256 архива. stdin-редирект: имена файлов с пробелами не влияют на вывод.
# sha256sum/shasum: hash — ПЕРВОЕ поле; openssl dgst: hash — ПОСЛЕДНЕЕ.
# Exit code утилиты берётся до awk (POSIX pipeline без pipefail его маскирует).
sha256_of() {
    f=$1
    if command -v sha256sum >/dev/null 2>&1; then
        sum=$(sha256sum < "$f") || err "не удалось вычислить SHA256"
        sum=$(printf '%s\n' "$sum" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        sum=$(shasum -a 256 < "$f") || err "не удалось вычислить SHA256"
        sum=$(printf '%s\n' "$sum" | awk '{print $1}')
    elif command -v openssl >/dev/null 2>&1; then
        sum=$(openssl dgst -sha256 < "$f") || err "не удалось вычислить SHA256"
        sum=$(printf '%s\n' "$sum" | awk '{print $NF}')
    else
        err "не найдена утилита sha256 (sha256sum/shasum/openssl)"
    fi
    case $sum in
        ''|*[!0-9a-f]*) err "утилита sha256 вернула некорректную сумму: $sum" ;;
    esac
    [ "${#sum}" -eq 64 ] || err "утилита sha256 вернула некорректную сумму: $sum"
    printf '%s\n' "$sum"
}

# Список членов tar.gz: ровно один regular-файл $BIN_NAME
check_tar_members() {
    archive=$1
    # явный || err: exit status tar не маскируется следующим элементом pipeline
    members=$(tar -tzf "$archive") || err "не удалось прочитать архив"
    count=$(printf '%s\n' "$members" | wc -l)
    [ "$count" -eq 1 ] || err "в архиве неожидаемое число файлов ($count)"
    [ "$members" = "$BIN_NAME" ] || err "в архиве неожидаемый файл: $members"
    long_list=$(tar -tvzf "$archive") || err "не удалось прочитать архив (список)"
    type_flag=$(printf '%s\n' "$long_list" | cut -c1)
    [ "$type_flag" = '-' ] || err "член архива не является обычным файлом"
}

# Удаляем ТОЛЬКО пути, сохранённые в переменные после нашего собственного создания
cleanup() {
    if [ -n "${staging:-}" ]; then
        rm -f "$staging"
    fi
    if [ -n "${tmp_dir:-}" ] && [ -d "$tmp_dir" ]; then
        rm -rf "$tmp_dir"
    fi
}

# HUP/INT/TERM: cleanup и ненулевой выход; установка не продолжается
on_signal() {
    exit 130
}

main() {
    install_dir=

    while [ $# -gt 0 ]; do
        case $1 in
            --install-dir)
                [ $# -ge 2 ] || err "--install-dir требует путь"
                [ -n "$2" ] || err "--install-dir: путь не может быть пустым"
                install_dir=$2
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                err "неизвестный аргумент: $1"
                ;;
        esac
    done

    detect_target

    # Проверки каталога установки — ДО любой сетевой активности
    if [ -z "$install_dir" ]; then
        [ -n "${HOME:-}" ] || err "HOME не задан; укажите --install-dir явно"
        install_dir=$HOME/.local/bin
    fi
    [ "$install_dir" != / ] || err "некорректный каталог установки"
    # Относительный путь (в т.ч. начинающийся с '-') нормализуем к абсолютному:
    # иначе mkdir/mv могут интерпретировать его как option
    case $install_dir in
        /*) ;;
        *) install_dir="$(pwd)/$install_dir" ;;
    esac

    latest_tag

    # umask 077: наши файлы (в т.ч. staging) недоступны другим пользователям
    umask 077

    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/tor-socks5.XXXXXX") || err "не удалось создать временный каталог"
    trap cleanup EXIT
    trap on_signal HUP INT TERM

    archive_name="$BIN_NAME-$tag-$target.tar.gz"
    curl -fsSL --proto '=https' --proto-redir '=https' --max-time 600 -o "$tmp_dir/$archive_name" \
        "https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$tag/$archive_name" \
        || err "не удалось скачать $archive_name"
    curl -fsSL --proto '=https' --proto-redir '=https' --max-time 60 -o "$tmp_dir/$archive_name.sha256" \
        "https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$tag/$archive_name.sha256" \
        || err "не удалось скачать $archive_name.sha256"

    expected_hash "$tmp_dir/$archive_name.sha256" "$archive_name"
    actual=$(sha256_of "$tmp_dir/$archive_name")
    [ "$actual" = "$EXPECTED_SUM" ] || err "SHA256 не совпадает (ожидалось $EXPECTED_SUM, получено $actual)"

    check_tar_members "$tmp_dir/$archive_name"

    if [ -e "$install_dir" ] && [ ! -d "$install_dir" ]; then
        err "путь установки существует и не является каталогом: $install_dir"
    fi
    mkdir -p "$install_dir" || err "не удалось создать каталог установки: $install_dir"
    [ -d "$install_dir" ] || err "каталог установки недоступен: $install_dir"

    # Reject: назначение — существующий каталог (в т.ч. symlink-to-dir),
    # иначе mv вложил бы candidate внутрь него
    if [ -d "$install_dir/$BIN_NAME" ]; then
        err "путь назначения является каталогом: $install_dir/$BIN_NAME"
    fi

    # Извлечение только ожидаемого файла через -xO в staging-файл рядом с destination
    staging=$(mktemp "$install_dir/.tor-socks5.XXXXXX") || err "не удалось создать staging-файл"
    tar -xOzf "$tmp_dir/$archive_name" "$BIN_NAME" > "$staging" \
        || { rm -f "$staging"; err "не удалось извлечь бинарник"; }
    [ -s "$staging" ] || { rm -f "$staging"; err "извлечённый бинарник пуст"; }
    chmod 755 "$staging"
    mv -f "$staging" "$install_dir/$BIN_NAME" || { rm -f "$staging"; err "не удалось установить бинарник"; }

    # успех: staging больше не наш — из cleanup-трекинга убран
    staging=
    trap - EXIT HUP INT TERM
    rm -rf "$tmp_dir"
    tmp_dir=

    printf 'Установлено: %s/%s (релиз %s)\n' "$install_dir" "$BIN_NAME" "$tag"
    printf 'Запуск: %s/%s\n' "$install_dir" "$BIN_NAME"
    printf 'Если каталог не в PATH — запускайте по полному пути.\n'
}

main "$@"
