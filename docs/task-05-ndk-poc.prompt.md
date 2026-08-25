Работай в D:\dev\rust\tor-socks5, ветка `android-ffi` (уже создана и активна — проверь `git branch --show-current`, если не на ней — переключись).

ВАЖНО про git-гигиену: в рабочем дереве уже есть ЧУЖИЕ незакоммиченные изменения, не относящиеся к этой задаче: `docs/upstream-reports.md` (изменён), `docs/upstream/` (новый), а также временный файл `research-android-surface.prompt.md` в корне репозитория. НЕ трогай их, НЕ коммить их. Когда будешь коммитить свою работу — используй `git add <конкретные пути>` для файлов, которые сам создал/изменил (типично: `.cargo/config.toml`, возможно `Cargo.toml`/`Cargo.lock`, новый md-отчёт если создашь). НИКОГДА не используй `git add -A` или `git add .`.

## Задача

Настроить кросс-компиляцию всего Cargo-workspace (arti-client + vendor-патчи tor-dirclient/tor-dirmgr/saturating-time/tor-chanmgr/tor-guardmgr, lyrebird/ptrs-gesher obfs4, static-sqlite feature) под 4 Android ABI: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android`.

Цель этой задачи — ТОЛЬКО проверить и настроить сборку существующего кода, НЕ писать новый Rust-код (новый FFI-крейт будет в отдельной задаче позже).

### Шаги

1. Установи Android NDK. `ANDROID_HOME`/`ANDROID_SDK_ROOT` уже прописаны в реестре через `setx` на `D:\system_artefact\android-sdk`, но в ТЕКУЩЕЙ shell-сессии эти переменные не видны (setx влияет только на новые процессы после перезапуска терминала) — либо передавай пути инлайн в командах (`ANDROID_HOME=D:\system_artefact\android-sdk ...`), либо используй полные пути к `sdkmanager`/`cmdline-tools`. Скачай `cmdline-tools` с https://developer.android.com/studio#command-tools если их ещё нет, распакуй в `D:\system_artefact\android-sdk\cmdline-tools\latest`, затем `sdkmanager --install "ndk;27.0.12077973" "platform-tools"` (актуальную версию NDK уточни, 27.x — LTS на момент задачи).
2. Установи `cargo-ndk` (`cargo install cargo-ndk`) — он сам находит NDK через `ANDROID_NDK_HOME`/`ANDROID_HOME`.
3. Добавь Rust-таргеты: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android`.
4. Настрой `.cargo/config.toml` (или таргет-специфичные секции) с правильными linker/ar путями на NDK-тулчейн (обычно через `cargo-ndk`, который сам подставляет `CARGO_TARGET_<ARCH>_LINKER` — предпочти использовать `cargo ndk -t <abi> build ...` напрямую, а не ручной config.toml, если это надёжнее).
5. Собери **сначала только aarch64-linux-android** (основной ABI реальных устройств, приоритет): `cargo ndk -t arm64-v8a -o target/android-out build -p socks5-proxy --release` (или ближайший рабочий вызов — экспериментируй с флагами). Итеративно чини ошибки компиляции/линковки.
6. Известные из предыдущего ресёрча риски, которые нужно ПОДТВЕРДИТЬ РЕАЛЬНОЙ СБОРКОЙ (не верь ресёрчу на слово):
   - `ring 0.17.14` — заявлена поддержка Android (LINUX_ABI в build.rs, pregenerated asm), но не проверялась реальной сборкой.
   - `libsqlite3-sys`/`rusqlite` (static-sqlite feature) — bundled sqlite3.c компилируется через `cc`, должен быть ок с NDK-clang, но не проверялось.
   - `zstd-sys` — аналогично, через `cc`.
   - `daemonize`/`service-manager` — должны просто компилироваться (не тестируются в рантайме на этом этапе).
7. После успешной сборки aarch64 — прогони остальные 3 ABI (armv7, x86_64, i686). Если что-то не собирается на конкретном ABI — задокументируй проблему подробно в коммите/отчёте, не обязательно чинить всё немедленно, но aarch64-linux-android ДОЛЖЕН собраться полностью — это блокер для всех последующих задач.

### Коммит

Когда aarch64 (и в идеале остальные ABI) собираются: закоммить только относящиеся к задаче файлы (`.cargo/config.toml`, изменения в `Cargo.toml` если понадобились target-specific правки, НЕ `Cargo.lock` если не менялся осознанно) с сообщением в духе `build: add Android NDK cross-compile targets (cargo-ndk)`. Одним или несколькими логическими коммитами.

### Отчёт

В конце выведи как финальный текст: что собралось (какие ABI), что не собралось и почему (если есть), какие версии NDK/cargo-ndk использовались, хэш(и) созданных коммитов.
