Работай в D:\dev\rust\tor-socks5, ветка `android-ffi`. Задача #11 (JNI FFI-крейт `packages/android-ffi`, libtorsocks5.so) должна быть уже завершена и закоммичена — проверь `git log --oneline -10`, прочитай, что там появилось (`packages/android-ffi/`, возможно рефакторинг `apps/socks5-proxy/src/config.rs`/`socks5.rs` в `packages/proxy-config`/`packages/socks5-proto`), прежде чем начинать — тебе нужно опираться на актуальное состояние кода, а не на устаревшие предположения.

ВАЖНО про git-гигиену: НЕ трогай/не коммить чужие файлы: `docs/upstream-reports.md`, `docs/upstream/`, любые `*.prompt.md` в корне. `git add <конкретные пути>`, никогда `-A`/`.`.

## Контекст

`arti` сам спавнит исполняемый файл как PT-процесс для obfs4/webtunnel (не наш код re-exec'ает себя) — путь берётся из `TransportConfig`, который берёт `current_exe()`, если не задан override через `TOR_PT_BINARY` (уже реализовано в задаче #10, коммит `623fc6b`). В JNI-архитектуре (задача #11) нет "нашего" исполняемого файла — движок это dlopen'нутая библиотека `libtorsocks5.so`, у неё нет `current_exe()`, указывающего на что-то осмысленное. Поэтому нужен ОТДЕЛЬНЫЙ маленький бинарник специально для PT-режима, который arti сможет заэкзекутить как child-процесс.

## Задача

Новый workspace-член `apps/pt-helper` (обычный бинарник, не cdylib). `main.rs` должен повторять PT-диспетчер из `apps/socks5-proxy/src/main.rs` (найди актуальные номера строк — искать проверку переменной окружения `TOR_PT_MANAGED_TRANSPORT_VER`, которая ведёт в `lyrebird::run()`). Скопируй именно эту диспетчерскую логику, БЕЗ остального (clap-парсинг, config.rs, server.rs, users_cli, bridges_cmd и т.д. не нужны — это должен быть минимальный бинарник). Добавь `"apps/pt-helper"` в `[workspace] members` корневого `Cargo.toml`. Зависимости — по минимуму (то, что реально нужно для `lyrebird::run()`, посмотри что использует main.rs для этого пути).

Если `TOR_PT_MANAGED_TRANSPORT_VER` не задана (бинарник запущен не как PT) — разумное поведение: короткое сообщение в stderr и exit code != 0 (это вспомогательный бинарник, не предназначен для прямого запуска пользователем).

## Сборка

Собери под все 4 Android ABI: `cargo ndk -t <abi> -o <dir> build -p pt-helper --release` (для бинарного крейта `-o` может не сработать — см. находку задачи #5 про socks5-proxy: там `-o` ломался с "No usable artifacts produced by cargo" для binary crate; если так же будет для pt-helper, убери `-o` и найди артефакт в `CARGO_TARGET_DIR=D:\dev\rust\.cargo-target\<triple>\release\pt-helper`). ANDROID_NDK_HOME=D:\system_artefact\android-sdk\ndk\27.2.12479018, ANDROID_HOME=D:\system_artefact\android-sdk — передавай инлайн. Подтверди ELF-архитектуру через `file` на каждый артефакт (как в задаче #5).

Также убедись, что host-сборка (`cargo build -p pt-helper`) работает и не сломала остальной workspace (`cargo build --workspace`).

## Коммит

`feat: standalone PT dispatcher binary for Android exec` — точечный git add.

## Отчёт

Финальный текст: путь к бинарнику в каждом target-triple, статус сборки по всем 4 ABI + host, хэш коммита. Напомни (для следующей задачи про упаковку в Orbot): итоговый файл должен лечь в `app/src/main/jniLibs/<abi>/libtorpthelper.so` (переименование при копировании) и exec разрешён только из `nativeLibraryDir`, не из `filesDir` (W^X/SELinux на Android).
