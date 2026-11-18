# SDK: доработки по ревью — план спринта

- **Дата:** 2026-11-17
- **Статус: выполнен (2026-11-18).** H0–H21 влиты (PR #118–#143), живая проверка H22 пройдена на release-бинарнике: бутстрап через мосты, собственный .onion с правильным адресом, `onion remove` во время старта (сервис не запускается), Ctrl-C при старте и Ctrl+Break в работе дают код 0, INFO-логи продуктовых крейтов на месте. Проверка нашла регрессию H13 (каталог keystore сравнивался с `<base>/keystore`, а не с `<base>/state/keystore`, из-за чего не запускался ни один сервис); исправлена в #144. Отклонения от плана: оракул use-tree оставлен (снапшот rustdoc-JSON требует nightly, H18.6); `sleep(500ms)` при остановке сервера оставлен с обоснованием (в runtime нет события завершения PT, H17.5); бинарник подключён к фасаду с фичами `pt` и `auth`, а не `full` (иначе `--no-default-features` получил бы onion-стек), `tor-socks5-server` остаётся прямой зависимостью (H21). SDK-13 в спринт не входил.
- **Дополнение (2026-11-18, PR #146–#149).** Остаток H19 закрыт: тесты `validate_owner_routes`, `select_anchor` и выбора якоря в сборщике настроек, швы `top_up_with` и `wait_for_address_with` для решений `top_up_working_with_pt` и ожидания адреса onion (сквозная цепь хоста через живой arti уже покрыта `host/tests.rs` и `host/serve_tests.rs`); счёт `yield` в ожиданиях серверных тестов заменён ожиданием в реальном времени с границей (`wait_for_permit_taken`, `without_auto_advance`, ожидание отмены в `phase_shutdown`, окна lock-пробы хоста onion); убран частный путь из `scripts/build-android.ps1`. Живая проверка на release-бинарнике нашла ещё одну недоработку: `bridges fetch` передавал в SDK токен отмены, который никто не отменял, и Ctrl-C убивал процесс в середине зондирования; теперь первый стоп-сигнал отменяет токен («bridge fetch cancelled», код 1), проверено реальным Ctrl-C. `users` с TOFU-аккаунтом и SOCKS5-аутентификацией проверены на живом бинарнике (правки пользователей применяются после перезапуска, как задокументировано). Не сделано: onion на Linux проверяется только CI (живая проверка выполнялась на Windows); SDK-13 (android-ffi) остаётся за владельцем у устройства.
- **Основа:** ревью SDK на main `c26e141` (2026-11-17) в четыре среза: `tor-socks5-runtime`, `tor-socks5-server`, `tor-socks5-onion`, фасад `tor-socks5` против бинарника. Около 90 находок. Самые серьёзные перепроверены по коду: устаревший снимок в хосте onion, `Startup` вместо `Cancelled`, мёртвые зависимости бинарника. Пункты с пометкой «предположение» исполнитель проверяет по коду (в том числе по вендорному arti) **до** правки.
- **Предыдущий план:** [sdk-coverage-plan.md](sdk-coverage-plan.md). Он выполнен, кроме SDK-13 (`android-ffi`, по D8 — только вместе с владельцем у устройства). SDK-13 в этот спринт не входит.

## 1. Цель, критерий приёмки, не-цели

**Цель.** SDK, который встраивающее приложение может использовать без скрытых ловушек. Он не пишет в текущий каталог, не отменяет чужие токены, не трогает глобальные ресурсы приложения, корректно останавливается за ограниченное время, не теряет ошибки и не открывает onion-сервис под чужим адресом. Тесты должны проверять продовый код.

**Критерий приёмки** (проверяет CI, не локально):

1. Каждая находка из §4 либо исправлена с тестом, который падает на старом коде, либо закрыта с записанной причиной («не воспроизводится», «предположение не подтвердилось»).
2. CI исполняет тесты фасада на каждом наборе фич (а не только `check`).
3. Поведение бинарника для оператора не меняется: команды, формат конфига и ключей, строки логов, которые проверяют тесты, коды выхода. Исключения перечислены в задачах явно: H7 — `Cancelled` вместо ошибки при Ctrl-C во время старта; H17 — проверка DNS при upstream до bind.
4. Живая проверка H22 пройдена.

**Не-цели.** Новые возможности сверх находок ревью. Поднятие версий (0.2.0 остаётся). Публикация и теги. SDK-13. Заморозка semver: SDK не опубликован (`publish = false`), поэтому несовместимые изменения API допустимы (D-H6).

## 2. Решения владельца

Рекомендации приняты по умолчанию. Задачи, которые от решения зависят, помечены.

| # | Вопрос | Рекомендация | Альтернатива | Задачи |
|---|---|---|---|---|
| D-H1 | SDK без `config_path` | Явный путь обязателен: `ServerBuilder` без пути → `ServerError::Config` на старте, `fetch_bridges(None)` → ошибка, фоновые задачи получают путь, а не `Option`, и читают без автосоздания. Бинарник передаёт свой путь, как сейчас. | Оставить `None`, но с `warn!` и документацией | H10, H13 |
| D-H2 | Нет файла пользователей | Как в CLI (без файла — без аутентификации) плюс один `warn!` при старте и строка в README | Для SDK — отказ (fail-closed) | H13 |
| D-H3 | Язык ошибок и логов в библиотеках | Английский везде (так уже пишется большинство) | Оставить как есть | H9, H20 |
| D-H4 | Писатель хранилища мостов | Свой экземпляр на каждый запуск сервера, им владеет `ServerHandle`. `init_global`/`close_global` остаются приложению, сервер их не трогает. | Глобальный, но сервер не закрывает чужой | H16 |
| D-H5 | Бинарник на фасаде | Да, последней задачей (H21): это лучшая проверка цели «SDK покрывает бинарник» | Нет | H21 |
| D-H6 | Несовместимые изменения API SDK | Допустимы без смены версии (SDK берут по git-тегу, тег только по просьбе) | Совместимые обёртки | все |

## 3. Порядок работ

Одна задача = один PR. Зависимости — по общим файлам и по смыслу. Одновременно в работе не больше трёх задач: так держит ёмкость CI (macOS-задачи) и проверка результатов.

| Волна | Задачи (можно параллельно) | Зависят от |
|---|---|---|
| 0 | H0 (этот план) | — |
| 1 | H1, H2, H3, H5, H6, H7, H8, H9 | H0 |
| 2 | H4 ← H1; H10 ← H9; H11 ← H7, H9; H12 ← H7; H16 ← H5, H7 | волна 1 |
| 3 | H13 ← H1, H10, H11; H14 ← H11 | волна 2 |
| 4 | H15 ← H9, H10, H13; H17 ← H7, H8, H11, H14, H16; H18 ← H2, H6, H12, H13, H14 | волна 3 |
| 5 | H19 ← H4, H15, H17; H20 ← H17, H18 | волна 4 |
| 6 | H21 ← H18, H20; H22 ← все | волна 5 |

Внутри волны 1 сначала идут исправления безопасности и корректности (H1, H2, H7, H5), затем остальное.

## 4. Задачи

Пути даны от корня репозитория. `onion/` = `apps/sdk/crates/onion/src/`, `runtime/` = `apps/sdk/crates/runtime/src/`, `server/` = `apps/sdk/crates/server/src/`. Номера строк — на `c26e141`; к началу задачи они могут сдвинуться.

### H0 — PLAN: этот план в репозиторий
PR только с `docs/plans/sdk-hardening-plan.md`. Приёмка: влит.

### H1 — ONION-HOST: файл — источник истины, проверка опубликованного адреса, отмена, статусы (high)
1. Хост берёт ключи из снимка конфига, сделанного до бутстрапа. Замок keystore он берёт только после бутстрапа, и `onion remove` или `new --force` за это время откатываются: удалённый сервис публикуется, его секрет возвращается в `hss/<nick>/`. Нужно под замком перечитать сервисы из файла и строить план из пересечения записей файла с включёнными никами снимка. Запись, которой в файле нет или у которой другой `key`, не запускается: `warn!` и статус `Failed`. Места: `onion/host/mod.rs:352-354`, `onion/keys/identity.rs:90-92,203`, `server/server/server.rs:334-337`.
2. Адрес, который settle записал в keystore, сверяется с тем, что опубликовал arti: settled-адрес передаётся в `service_manager` и сравнивается с `service.onion_address()`. При расхождении сервис удаляется, статус `Failed{AddressMismatch}`. Места: `onion/host/mod.rs:378-394,529-541`. **Предположение:** без ключа arti генерирует новый HsId — проверить по вендорному tor-hsservice.
3. Отмена: `select!` с `token.cancelled()` вокруг ожидания замка (до `CLI_LOCK_WAIT` = 60 с), проверка `is_cancelled()` перед `prepare_all` и перед запуском менеджеров. Места: `onion/host/mod.rs:329,352,377-395`.
4. Статусы на путях отказа:
   - паника `prepare_all` → все сервисы `Failed{Internal}` (сейчас они навсегда остаются `Preparing`);
   - ошибка `PathLock::open` различает «занят» (`KeystoreLockHeld`) и «недоступен» (новый вариант);
   - причина отказа settle (в том числе `InvalidNickname`) передаётся в `PreparedService`.

   Места: `onion/host/mod.rs:330-339,357-364,454-466`.
5. Если settle перезаписывает в keystore другую идентичность, пишется `warn!` со старым и новым адресом, без секретов (`onion/keys/identity.rs:90-92`).
6. `ensure` (используют только тесты) → `#[cfg(test)]` (`identity.rs:122`). Модули `host::forward` и `host::serve` → `pub(crate)` (`host/mod.rs:60-61`). Неверный комментарий `host/mod.rs:595`.

**Приёмка.** Тесты:
- `remove` во время бутстрапа: сервис не публикуется, ключа в keystore нет;
- `new --force` во время бутстрапа: публикуется новый адрес;
- расхождение адреса → `Failed{AddressMismatch}`;
- отмена во время ожидания замка: выход быстрее чем за 1 с, файл не меняется;
- паника `prepare_all` → `Failed`.

**Файлы:** `onion/host/{mod,status}.rs`, `onion/keys/identity.rs`, `server/onion/service.rs`.

### H2 — ONION-KEYS: экспорт секрета, временные файлы, узкое API (medium, безопасность)
1. Экспорт секрета:
   - `OpenOptions::create_new(!force)` + `mode(0o600)` + `O_NOFOLLOW` (unix);
   - при `force` — временный файл 0600 в том же каталоге и `rename`;
   - проверку `exists()` убрать (сейчас она не атомарна, а dangling symlink её проходит);
   - исправить комментарий про Windows.

   Места: `onion/keys/store.rs:253-259`, `onion/keys/ops.rs:135-139`.
2. Секрет не пишется во временный каталог ОС: ключ разбирается в памяти или стейджится внутри каталога keystore, буферы — `Zeroizing`. Места: `onion/keys/store.rs:203-216,231-244`.
3. `KeysError::InvalidNickname` должен реально создаваться: `.map_err(KeysError::InvalidNickname)` вместо `.context(..)` (`store.rs:45,72-74`), плюс тест.
4. `Recorded.ports_enabled` — фактическое `enabled && !ports.is_empty()` из замыкания `update_onion_services`. Сейчас `onion new --force svc` без `--port` печатает «service is disabled», хотя порты сохранены. Места: `onion/keys/ops.rs:96,167-168`, `apps/socks5-proxy/src/commands/onion/commands.rs:161-166`.
5. Vanity-поиск не держит замок keystore часами (сейчас сервер, стартовавший во время поиска, получает `KeystoreLockHeld`). Новый порядок: проверка замены → поиск без замка → замок → повторная проверка `identity_exists` → запись. Места: `ops.rs:84-92`, `commands/onion/commands.rs:193-196`.
6. Низкоуровневые `keys::{open, insert, generate, remove_all, lock_with, write_secret_file, specifier::*}` и `prepare_all` → `pub(crate)` (или за `test-seams`), если вне крейта их использует только тестовый код. `apps/sdk/tests/surface.rs:114` больше не закрепляет `prepare_all`.
7. Тексты ошибок SDK не упоминают флаги CLI («pass --force», «stop tor-socks5 first»); подсказки добавляет CLI.

**Приёмка.** Тесты:
- экспорт не идёт по symlink и не перезаписывает файл без `force` (unix);
- права 0600 (unix);
- `InvalidNickname` создаётся;
- `Recorded` верен для `new --force` без портов и для `import` выключенной записи.

**Файлы:** `onion/keys/{store,ops,mod}.rs`, `apps/socks5-proxy/src/commands/onion/commands.rs`, `apps/sdk/tests/surface.rs`.

### H3 — ONION-VANITY: vanity и разбор адреса без паник (medium)
1. `vanity::search`:
   - дедлайн через `checked_add` (сейчас `--timeout 9999999999999999999s` вызывает панику, `vanity.rs:170`);
   - `thread::Builder::spawn` с обработкой ошибки: выставить stop, сделать join, вернуть `Err` (сейчас уже запущенные воркеры крутятся вечно, `:179`);
   - верхняя граница числа потоков (значение исполнитель выбирает и обосновывает);
   - паника воркера даёт отдельный исход, а не `TimedOut` (`:218`).
2. `estimate`/`expected_attempts`: при `!(rate > 0.0)` (NaN, 0) → `Duration::MAX`; `try_from_secs_f64(..).unwrap_or(Duration::MAX)`; `assert!` заменить на `Option` или кламп. Места: `vanity.rs:91,102-103`.
3. `vanity::measure_rate` в SDK; `warmup_rate` из CLI (`apps/socks5-proxy/src/commands/onion/vanity.rs:44-66`) вызывает его вместо своего цикла воркеров.
4. `parse_onion_address`:
   - отдельная ошибка `MissingSuffix` (сейчас тело из 56 символов без суффикса даёт «expected 56 chars, got 56»);
   - суффикс без учёта регистра.

   Места: `address.rs:58-64`.
5. `to_expanded_bytes` → `Zeroizing<[u8; 64]>`, digest SHA-512 сразу в `Zeroizing`. Места: `address.rs:120-122,138-140`; вызовы `keys/ops.rs:207`, `keys/identity.rs:308`. Комментарий `address.rs:306`.

**Приёмка.** Тесты: огромный timeout; rate равный 0, NaN или крошечный; тело без суффикса; `.ONION`; ошибка spawn (через шов или лимит).

**Файлы:** `onion/{vanity,address}.rs`, `apps/socks5-proxy/src/commands/onion/vanity.rs`.

### H4 — ONION-SERVE: DoS-лимиты и надзор за задачами хоста (medium) ← H1
1. Отдельный семафор только на фазу `rend.accept()`. Сейчас задача рандеву держит разрешение всю жизнь цепи, и 256 простаивающих цепей закрывают приём новых. Места: `onion/host/serve.rs:48,113,133,207-211`.
2. Лимит стримов на одну цепь: `max_concurrent_streams_per_circuit` в `OnionServiceConfigBuilder`, если он есть в вендорном arti, иначе свой счётчик.
3. Idle-таймауты для цепи и для стрима; `copy_bidirectional` с таймаутом простоя (`host/forward.rs:21`).
4. Справедливое деление глобального лимита (512) между сервисами: два «жадных» сервиса не должны съедать весь процесс.
5. Сначала соединение с целью, потом `accept`; при ошибке — `reject(End)`. Цель резолвится один раз при старте, а не на каждый стрим (`serve.rs:258-266`).
6. Надзор: `select!` на `token.cancelled()` и `children.join_next()`. При выходе serve-задачи или `Broken` — `children.shutdown()`, удаление сервиса, повтор с backoff; статус это отражает. Места: `host/mod.rs:563`, `serve.rs:115-117,339-351`. **Предположение:** `Broken` в tor-hsservice — терминальное состояние; проверить по вендорному коду.

**Приёмка.** Тесты на продовом коде, а не на голом `Semaphore`:
- простаивающие цепи не блокируют приём;
- одна цепь не забирает все стримы;
- выход serve-задачи → перезапуск;
- отказ соединения с целью → `reject`, CONNECTED не отправляется.

**Файлы:** `onion/host/{serve,forward,mod}.rs`.

### H5 — RT-WRITER: писатель хранилища мостов и реестр блокирующих задач (medium)
1. Актор берёт межпроцессный замок с ограничением (`PathLock::acquire_bounded`), а не бессрочно (`runtime/bridges/bridge_store_writer.rs:485`). Если замок занят — `Err("busy")`, изменения остаются для повтора.
2. `Op::Close` не ждёт в общей очереди за зависшей загрузкой: отдельный канал или `select!` с приоритетом.
3. Документацию `StoreWriter::apply` про панику привести к коду: снимок сохраняется, TS5-06 (`:266-269` против `:562-575`).
4. Реестр `BLOCKING_WORKERS`:
   - ячейка, завершившаяся ошибкой, не занимает лимит 64: `warn!` и перенос в ограниченный буфер отчётов (`bridge_maintenance/workers.rs:4,99-106,167-169,264-265`);
   - сообщения «verifier …» сделать нейтральными (`workers.rs:30,177,253,265`);
   - пустую обёртку `reap` убрать (`:148-150`).
5. Русский текст в doc `StoreWriter::close` перевести на английский (`bridge_store_writer.rs:286-289`, D-H3).

**Приёмка.** Тесты:
- держатель замка в другом потоке не вешает актор: `close()` завершается за бюджет;
- 65 паник подряд не блокируют новую блокирующую работу.

**Файлы:** `runtime/bridges/bridge_store_writer.rs`, `runtime/bridges/bridge_store_writer_tests/*`, `runtime/bridges/bridge_maintenance/workers.rs`.

### H6 — CI-SURFACE: тесты фасада исполняются на всех фичах, surface проверяет сигнатуры (medium)
1. `.github/workflows/ci.yml`, job `features` (`:520-521`): на каждом наборе фич `cargo test -p tor-socks5 --test surface` вместо `check` (тесты без сети); плюс `cargo test --doc -p tor-socks5 --features full`. Учесть ci_planner (fail-closed) и его тесты.
2. `apps/sdk/tests/surface.rs`:
   - `let _ = fn;` заменить приведениями к `fn(..) -> ..` по образцу `:174-192`;
   - `type_name().contains(..)` заменить проверкой полного пути;
   - добавить непокрытое: `ServerBuilder::{config_path, observation_sink, no_upstream, cancellation_token, subscribe}`, `ServerHandle::{wait, status}`, `ServerError::{stage, cleanup_error}`, `transfer_tasks`, `StoreWriter::apply`, `OnionHostConfig::new`, `OnionHostHandle::{shutdown, detach}`, функции keys для list/show/export/import/remove.

**Приёмка.** CI зелёный и действительно исполняет surface на всех наборах; в PR перечислено, какие сигнатуры теперь закреплены.

**Файлы:** `.github/workflows/ci.yml`, ci_planner (если затронут), `apps/sdk/tests/surface.rs`.

### H7 — SRV-LIFECYCLE: токены, отмена, статус и ошибки `Server` (high)
1. Токен вызывающего сервер не отменяет: внутри используется `child_token()`. Места: `server/api.rs:276-279,318,531,546`.
2. Резервация D5 (одна живая копия сервера на процесс) хранится как `Option<AdmissionReservation>` и освобождается через `take()` **до** `send_replace(Stopped)`. Сейчас сразу сделанный `start()` получает ложный `AlreadyRunning` (`api.rs:608-617`). Дальше:
   - тесты больше не обходят это spin-циклом (`tor/tor_watchdog/owners/tests/restart_tests.rs:132-156,603-629`);
   - подписчики при `AlreadyRunning` получают терминальный статус (`api.rs:316`);
   - `WorkerCompletion::drop` при остановке runtime не пишет «panicked».
3. Ctrl-C во время подготовки настроек даёт `Cancelled`, а не `Startup("истёк срок…")`. Токен передаётся в `SettingsInit`, внутри `block_on` — `select!`, как в `GlobalInit::start`; таймаут очистки после отмены даёт `Cleanup{Cancelled, ..}`. Места: `server/tor/tor_watchdog/owners/global_init.rs:125-131,270-279`, `server/server/server.rs:244-253`. Тест `owners/handler_tests.rs:195-198` переписать на `Cancelled`. Это изменение поведения бинарника: Ctrl-C во время старта даёт код 0.
4. Ошибки:
   - исходная ошибка не теряется, если очистка тоже упала (`global_init.rs:207,263,277-279,415`) — агрегация;
   - `ServerError` не дублирует сообщение в `{:#}` (`#[error(transparent)]` или нейтральный Display), у `Cleanup` есть `#[source]`, `ProducerFailures::source()` исправлен (`api.rs:107-145`, `owners/producers.rs:29-43`).
5. Неожиданный выход accept-цикла возвращает `Err`; doc `wait()` поправить (`server.rs:555-584`).
6. `PathLock::acquire_bounded` (до 60 с, `thread::sleep`) не выполняется на async-потоке — `run_fallible_blocking`. Места: `server/server/startup.rs:365`, `server.rs:132-134`.
7. Включённые onion-сервисы при upstream-egress не запускаются молча — явный `warn!`. Места: `server.rs:199-217` против `:333-353`.
8. `ServerBuilder::run_until(shutdown: impl Future) -> Result<(), ServerError>` с хореографией из бинарника (`apps/socks5-proxy/src/process/run.rs:77-130`; `wait_for_terminal` дублирует `api.rs:662-672`). Бинарник и `apps/sdk/examples/embedded_server.rs` переходят на него.
9. Фасад реэкспортирует `ServerStage` (`apps/sdk/src/lib.rs:208-210`); README перечисляет `ServerStage` и `DnsStartupPolicy` (`apps/sdk/README.md:308`).

**Приёмка.** Тесты:
- токен приложения жив после `shutdown()`;
- `start()` сразу после `Stopped` проходит без spin;
- отмена во время settings → `Cancelled`;
- `{:#}` без повторов;
- `run_until` останавливает сервер по future.

**Файлы:** `server/api.rs`, `server/server/{server,startup}.rs`, `server/tor/tor_watchdog/owners/{global_init,producers}.rs` и их тесты, `apps/socks5-proxy/src/process/run.rs`, `apps/sdk/{src/lib.rs, README.md, examples/embedded_server.rs}`.

### H8 — SRV-EGRESS: обработчики и egress (medium/low)
1. Гонка permit и JoinSet: permit отпускается раньше, чем задача видна завершённой, и при насыщении соединение закрывается без SOCKS-ответа. Нужно убрать дублирующую проверку `tasks.len() >= MAX_CONCURRENT_CONNECTIONS` или держать permit до reap. Места: `server/tor/tor_watchdog/owners/handlers.rs:57,201`.
2. Handle `registry.start_background(members)` хранить в `State` и делать по нему join в `close()` (`server/server/egress/tor_branch.rs:265`).
3. SOCKS-ответы:
   - `Failure::Closed` и `TimedOut` → `GeneralFailure`/`TtlExpired`;
   - `record_connect_failed` вызывается одинаково для всех ошибок;
   - таймаут owner'а не отдаётся как `Forbidden`.

   Места: `server/server/server.rs:844-850`, `tor_branch.rs:112-115,228`.
4. `is_ready` через атомарный флаг, а не `try_lock` (`owners/mod.rs:168`).
5. Лимит в 15 owner'ов — одна константа (`egress/route.rs:11`, `owners/mod.rs:20,321`, `owners/storage.rs:8`).

**Приёмка.** Тесты:
- при насыщении и освобождении слота новое соединение получает SOCKS-ответ;
- ответы на Closed/TimedOut;
- `is_ready` верен при удерживаемом lock.

**Файлы:** `server/tor/tor_watchdog/owners/{handlers,mod,storage}.rs`, `server/server/egress/{tor_branch,route}.rs`, `server/server/server.rs` (только обработка соединения; после H7 — rebase).

### H9 — RT-SHUTDOWN: остановка рантайма (medium, одна позиция — безопасность)
1. `BridgeManagerHandle::shutdown_with_timeout(budget)`. Сетевые этапы verifier, maintenance и watchdog уходят в `select!` с `token.cancelled()`, записи в хранилище сохраняются. Места: `runtime/bridge_manager.rs:145-147`, `bridges/bridge_verifier.rs:196-208`, `bridges/bridge_maintenance.rs:184-193`, `tor/tor_watchdog/tor_watchdog_runtime.rs:579-584,675`.
2. Паники фоновых задач не теряются: `shutdown` их возвращает или хотя бы пишет `warn!` (`bridge_manager.rs:146`).
3. `warm_bridge` вызывается под `timeout(15 s)` и с отменой (`bridges/bridge_warmer.rs:127`).
4. **Безопасность:** временный каталог verifier создаётся через `tempfile::Builder` на каждый батч, а не `temp_dir()/torsocks5-circuit-verify-{pid}` (`bridge_verifier.rs:294-295`).
5. `spawn_conn_health_logger` принимает токен (или уходит из фасада); экспортируется `run_conn_health_logger`. Места: `tor/conn_health.rs:282,364`, `apps/sdk/src/lib.rs:165-168`.
6. `TorHandle::new` выставляет активные мосты из настроек (или становится `pub(crate)`). Сейчас verifier, прогрев и failover молча ничего не делают. Места: `tor/tor_watchdog/tor_watchdog_health.rs:284-291`.
7. Мелочи:
   - мёртвый параметр `compute_deficit` (`bridge_maintenance.rs:302`);
   - `bail!` по-русски (`:282,406,409,422`, D-H3);
   - префикс логов «warm-pool:» в `bridge_maintenance/bridge_rank.rs:174,186`;
   - «detached» в doc `bridge_warmer.rs:43`;
   - сообщение `bridge_verifier.rs:821`;
   - `owner_settings.rs:37`;
   - ссылки на несуществующие модули `tor/tor_setup.rs:3-4`.
8. Тест `shutdown_sets_cancelled_and_reports_producers` проверяет `rx.borrow().cancelled` (`bridge_manager.rs:420-439`).

**Приёмка.** Тесты:
- `shutdown_with_timeout` с зависшей сетевой задачей возвращается за бюджет;
- паника задачи видна в результате;
- `warm_bridge` ограничен по времени.

**Файлы:** `runtime/bridge_manager.rs` (кроме `fetch_bridges`), `runtime/bridges/{bridge_verifier,bridge_warmer,bridge_maintenance}.rs`, `runtime/bridges/bridge_maintenance/bridge_rank.rs`, `runtime/tor/{conn_health,tor_setup}.rs`, `runtime/tor/tor_watchdog/*`, `apps/sdk/src/lib.rs`.

### H10 — RT-FETCH: `fetch_bridges` (high) ← H9
1. Отмена работает на всех этапах: настройки, bootstrap, drain. На ошибках выполняется тот же хвост: туннель освобождается, затем пауза 200 мс. Отмена во время финальной паузы не теряет уже записанный результат. Места: `runtime/bridge_manager.rs:328-388`.
2. В `FetchBridgesParams` добавляется `pt_binary`, он идёт в `build_tor_settings_with_pt` и `drain_pool_with_pt` (`bridge_manager.rs:328`, `fetch/fetch_merge/fetch_merge.rs:356`). Сейчас всегда используется `PtBinary::Environment`, и arti запускает exe приложения как PT.
3. Глобальные `pre_proxies` дают типизированную ошибку SDK. Проверка переносится из `apps/socks5-proxy/src/fetch/bridges_cmd.rs:25-30,52`, CLI использует ошибку SDK. Сейчас SDK проверяет мосты напрямую с адреса хоста, мимо pre-прокси.
4. `drain_pool`: конфиг загружается один раз, `config_path` проверяется до загрузки, `max_attempts = MAX_DRAIN_ATTEMPTS`. Места: `fetch_merge.rs:372,399-402,432`.
5. `config_path = None` → ошибка («no config file found», как в CLI), а не `Some(0)` и не новый файл в CWD (D-H1).
6. Обновить пример `apps/sdk/examples/bridge_fetch.rs` и README.

**Приёмка.** Тесты:
- отмена во время bootstrap или drain возвращается быстро;
- `pre_proxies` → ошибка без сетевых проб;
- `None` → ошибка, файл не создаётся;
- `pt_binary` доходит до настроек.

**Файлы:** `runtime/bridge_manager.rs` (`fetch_bridges`), `runtime/fetch/fetch_merge/*`, `apps/socks5-proxy/src/fetch/bridges_cmd.rs`, `apps/sdk/{examples/bridge_fetch.rs, README.md}`.

### H11 — PT-SERVER: PT-политика сервера (high) ← H7, H9
1. `ServerBuilder::pt_binary(PtBinary)` доходит до `SettingsInit` (`build_tor_settings_with_pt`), `restricted_owner_settings_with_pt` и `bridge_producers::launch` через `BridgeManagerConfig{settings, pt_binary}`. Места: `server/tor/tor_watchdog/owners/global_init.rs:127`, `owners/producers.rs:299`, `server/fetch/bridge_producers.rs:20`, `runtime/bridge_manager.rs:75-81`.
2. `runtime/tor/tor_watchdog/owner_settings.rs:66-81` вызывает `pt::resolve_pt_binary` вместо своей копии.
3. Публичные обёртки с жёстким `PtBinary::Environment` → `pub(crate)` или удаление: `bridge_maintenance.rs:107` (`spawn`), `bridge_verifier.rs:173`, `fetch_merge.rs:351` (`drain_pool`).
4. README фасада описывает PT-политику для `server` и `fetch_bridges`.

**Приёмка.** Тест: `Explicit(path)` из builder доходит до настроек всех клиентов (наблюдатель SDK14). Бинарник не меняется (`Environment`).

**Файлы:** `server/api.rs`, `server/tor/tor_watchdog/owners/{global_init,producers}.rs`, `server/fetch/bridge_producers.rs`, `runtime/{pt.rs, bridge_manager.rs, tor/tor_watchdog/owner_settings.rs}`, обёртки из п. 3, `apps/sdk/README.md`.

### H12 — HOST-HELPERS: процессная инициализация для встраивающего хоста (high) ← H7
1. Функция `tor_socks5::install_crypto_provider()`: хост вызывает её явно (R1). **Предположение:** без провайдера бутстрап падает (основание — комментарии в тестах `onion/host/mod.rs:842-846`, `runtime/tor/tor_watchdog/tor_watchdog_tests.rs:5-13`); проверить по коду.
2. Фича `pt` и `tor_socks5::pt::run_if_managed_transport() -> Option<Result<()>>` — busybox-диспетчер lyrebird из `apps/socks5-proxy/src/main.rs:64-83`.
3. Логи: функция, которая собирает слой из `LogConfig` и возвращает `(impl Layer, WorkerGuard)`, не устанавливая его глобально. Поведение — как в `apps/socks5-proxy/src/process/logging.rs:41-201`: stdout, stderr или файл, ANSI по TTY, `NO_COLOR`, фильтр `LogConfig::to_filter`.
4. `bind_child_processes_to_self()`: Job Object из `process/children.rs:11-70`; вне Windows — no-op с документацией.
5. Бинарник переходит на эти функции. Tor-примеры (`tor_runtime.rs`, `onion_host.rs`, `bridge_fetch.rs`) ставят провайдер и фильтр. README.

**Приёмка.** Бинарник не меняется: те же строки логов и коды выхода. Тест: слой из `LogConfig` пропускает INFO продуктовых целей. Новые зависимости проходят через планировщик.

**Файлы:** runtime (новый модуль), `apps/sdk/{src/lib.rs, Cargo.toml, examples/*, README.md}`, `apps/socks5-proxy/src/{main.rs, process/{logging,children}.rs}`.

### H13 — DATA-DIR: без записей в текущий каталог (high) ← H1, H10, H11; D-H1, D-H2
1. `ServerBuilder` без пути конфига → `ServerError::Config` (D-H1). Места: `server/api.rs:204`; пути пользователей и DNS-кэша `server/server/server.rs:139-140`, `server/server/dns_wiring.rs:42`.
2. Runtime:
   - фоновые задачи получают путь, а не `Option`;
   - конфиг читается без автосоздания;
   - `cfg` у `start` документируется как стартовый снимок.

   Места: `bridge_maintenance.rs:234,351`, `bridge_warmer.rs:100`, `tor_watchdog_runtime.rs:330`, `fetch_merge.rs:372,402`; автосоздание — `packages/proxy-config/src/lib.rs:906-919`.
3. Пути по умолчанию на SDK-путях не используются, без пути — ошибка: `runtime/tor/tor_setup.rs:305-310` (`arti-data`), `packages/bridge-store/src/persistence.rs:233`, `packages/auth/src/registry/users_config.rs:64`. Бинарник по-прежнему разрешает пути сам.
4. Нет файла пользователей → `warn!` при старте и строка в README (D-H2).
5. `arti_keystore_dir` переезжает в Tor-free `proxy_config` (`runtime/tor/tor_setup.rs:315`). Обёртки удаляются: `apps/socks5-proxy/src/commands/onion/store.rs:18-20`, `server/onion/service.rs:18-20`. `OnionHostConfig` выводит каталог keystore из state dir у `TorHandle` или проверяет его (`onion/host/mod.rs:135-136,155`).
6. README и `examples/embedded_server.rs`: путь обязателен.

**Приёмка.** Тесты:
- сервер, `start` рантайма и `fetch_bridges` без пути возвращают ошибку до любого файлового I/O;
- `OnionHostConfig` с чужим каталогом даёт ошибку.

Бинарник не меняется.

**Файлы:** `server/{api.rs, server/server.rs, server/dns_wiring.rs, onion/service.rs}`, runtime (фоновые задачи, `tor_setup.rs`), `packages/{proxy-config,bridge-store,auth}`, `onion/host/mod.rs`, `apps/socks5-proxy/src/commands/onion/store.rs`, README, примеры.

### H14 — RT-PRODUCERS: проводка производителей мостов в runtime (medium) ← H11
1. `runtime::launch_producers(..)` берёт тело из `server/fetch/bridge_producers.rs:25-54` (ветка pre-endpoint, failover-watchdog) и проводку из `server/server/server.rs:294-300` (`set_recovery_notifier`, `set_needed(auto_fetch && preferred_missing)`). Экспортируется в фасаде.
2. Сервер вызывает её; пример `apps/sdk/examples/tor_runtime.rs` тоже.

**Приёмка.** Поведение сервера не меняется (существующие тесты). Тест: `set_needed` выставляется, когда предпочтительного транспорта нет.

**Файлы:** runtime (новый модуль), `server/fetch/bridge_producers.rs`, `server/server/server.rs` (проводка), `apps/sdk/{src/lib.rs, examples/tor_runtime.rs}`.

### H15 — RT-BLOCKING: блокирующее I/O с async-потоков (medium) ← H9, H10, H13
1. Чтения `BridgeStore::load`, `Config::load_with_override`, `CandidatePool::load` и `.seeds` обернуть в `run_fallible_blocking` (правило TS19-01). Места: `tor/tor_setup.rs:136,208,466`, `bridges/bridge_maintenance.rs:351`, `bridge_maintenance/channel_probe.rs:102`, `bridges/bridge_warmer.rs:100,109`, `bridge_maintenance/bridge_rank.rs:183`, `tor/tor_watchdog/tor_watchdog_runtime.rs:330,339,848`, `fetch/fetch_merge/fetch_merge.rs:372,402,420`, `bridge_manager.rs:351,365`. Строки — актуальные после H9, H10 и H13.
2. Гейты TS19: ключ `(Site, PathBuf)` вместо `Site` (`tor/test_seams.rs:257-267`, `tor/ts19_tests.rs:272-302`). Сейчас при параллельном запуске тест может пройти ложно. Новые точки — для каждого перенесённого места.
3. Остатки:
   - `#[allow(dead_code)]` в `test_seams.rs:207-209`;
   - `AdmissionWorkers::track` пишет в общий реестр (`workers.rs:452-472`);
   - цикл из одного элемента `ts19_tests.rs:259`;
   - `#[allow(unused_imports)] pub use` в `tor_watchdog.rs:128`.

**Приёмка.** На каждое место — TS19-тест, устойчивый к параллельному запуску.

### H16 — SRV-ISOLATION: сервер не трогает глобальные ресурсы приложения (medium) ← H5, H7; D-H4
1. Писатель хранилища — свой экземпляр на каждый запуск сервера. `close_global` чужого writer'а не вызывается (`server/tor/tor_watchdog/owners/global_init.rs:236-241`, `server/server/server.rs:106-109,634`).
2. Сервер ждёт только блокирующие задачи своей группы (`spawn_fallible(.., Some(group))`), а не все `BLOCKING_WORKERS` (`owners/producers.rs:46-53,177-178`). Тест `restart_tests.rs:254-282` переписать.
3. Writer при остановке закрывается с дедлайном и retained-слотом (`server.rs:634`, `server/server/lifecycle.rs:70`).

**Приёмка.** Тесты:
- глобальный writer приложения жив после старта и остановки сервера;
- чужая блокирующая задача не задерживает старт и остановку;
- зависший flush не держит `shutdown()` дольше бюджета.

### H17 — SRV-REFACTOR: разбиение `run_server_inner` и честные тестовые швы (medium) ← H7, H8, H11, H14, H16
Это рефакторинг: поведение не меняется. Единственное исключение — п. 1, проверка DNS при upstream до bind.
1. `run_server_inner` (`server/server/server.rs:88-650`, около 560 строк) разбить на фазы: recovery, validate, bootstrap, producers, dns, serve, shutdown. Стадии монотонны. Проверка DNS при upstream (`:403`) идёт до bind.
2. `Egress::Tor` — именованная структура, а не кортеж из шести полей (`:62-72`).
3. Раскладка `#[path]` совпадает с модульной (`server.rs:928-952`, `server/lib.rs:8-25`); `use super::*` в `handlers.rs:1`.
4. `#[cfg(test)]`-хуки на task-local внутри продовых функций (`global_init.rs:49-99,110-124,318-352`) заменить инжектируемым швом (трейт или поле `ServerArgs`). Тестовые копии `shutdown_producers` (`server.rs:661-690`) и `onion_permitted` (`server/server/startup.rs:410-417`) удалить. Регрессии TS3-04 проверяют продовую хореографию остановки: join 120 с, abort, закрытие реестра и writer'а.
5. `sleep(500ms)` при каждой остановке (`server.rs:627`) — заменить ожиданием события или обосновать. Оборванный комментарий `:629-633`.

**Приёмка.** Все существующие тесты зелёные; новые тесты через шов исполняют продовый запуск producers и хореографию остановки.

### H18 — FACADE-CURATE: кураторство фасада, фичи, документация (medium) ← H2, H6, H12, H13, H14
1. `onion` — отобранная поверхность вместо `pub use ::tor_socks5_onion as onion` (`apps/sdk/src/lib.rs:90`). `tor` (`src/lib.rs:67`) не выносит наружу вендорные `DataStream`, `BridgeConfigBuilder`, `ChannelUsage`, `ExternalActivity` — либо README (`:414`) говорит правду.
2. Реэкспорт `CancellationToken`, `BridgeLine`, `time::OffsetDateTime`, `HsNickname` (или newtype). Бинарник убирает зависимость `tor-hsservice`, которая нужна ему только ради `HsNickname` (`apps/socks5-proxy/Cargo.toml:40-43`).
3. Фичи (`apps/sdk/Cargo.toml:26,43,47`):
   - `onion-host` включает `runtime`, `onion-keys` включает `config`;
   - `onion-service` слить с `onion-host` или задокументировать;
   - `config` не тянет SQLite (`bridge-verify-core`).

   В `surface.rs` добавить пробу импликаций (`fn _(h: runtime::TorHandle) -> onion::host::OnionHostConfig`).
4. `#![warn(missing_docs)]` в runtime и server и недостающие doc: `ObservationSink::new`, `set_recovery_notifier`, поля `ConnHealthSnapshot`, `TorHealth::successful_within`.
5. README:
   - `:161` — путь `tor_socks5::onion::host`;
   - `:262-264` — `move` в `apply`;
   - `:109` — `resolve_path`;
   - `:124-126` — реальные имена функций;
   - список Arti-фич в `src/lib.rs:23-24`.

   Метки SDK-x, D5 и QUARANTINE15 убрать из публичного rustdoc (`src/lib.rs:20,95,144,193`, `server/api.rs`).
6. Oracle `apps/sdk/tests/support/runtime_use_tree_oracle.rs` (586 строк токенайзера) заменить снапшотом публичного API (rustdoc JSON), если это получается без тяжёлых новых зависимостей. Иначе оставить и записать причину.

**Приёмка.** Матрица фич в CI зелёная, surface исполняется; блоки README соответствуют API.

### H19 — TESTS-QUALITY: честные тесты и флейки (medium) ← H4, H15, H17
1. Тесты, которые проверяют не продовый код, заменить тестами продовых путей или удалить с обоснованием:
   - `accept_loop_respects_concurrency_cap` (`server/server/listen/server_tests.rs:182-245`);
   - `accept_error_backoff_is_sane`;
   - `semaphore_caps_concurrent_forwards`;
   - `zeroize_actually_clears`;
   - `generate_produces_distinct_keys`;
   - `an_address_that_does_not_match_the_key_is_refused`;
   - `invalid_nickname_is_rejected_before_launch`;
   - `onion/host/ownership_tests.rs`;
   - smoke-тест `server/fetch/bridge_producers_tests.rs:11-13`.
2. Флейки:
   - TOCTOU портов: `restart_tests.rs:297-300`, `handler_tests.rs:132-134`;
   - busy-spin на `yield_now`: `restart_tests.rs:139-153,259-261,469-477`;
   - опрос через `thread::sleep` в async: `bridge_store_writer_tests/mod.rs:51-73`, `bridge_warmer.rs:225-234`, `panic_tests.rs:300-309`;
   - отрицательная проверка после `sleep(100ms)`: `backoff_tests.rs:94-99` → барьер;
   - фиксированный `temp_dir()` в тесте `ensure_bridges_file`: `server/server/startup.rs:166`.
3. Покрытие:
   - продовая цепочка хоста onion (`run_services`, `service_manager`, `wait_for_address`) через шов;
   - `build_tor_settings` без pre (активный срез → предпочтительный пул → obfs4 → seeds → ранжирование);
   - `refresh_candidate_pool`, `top_up_working_with_pt`, `validate_owner_routes`/`select_anchor`;
   - оркестрация циклов watchdog: статус через `watch`, cooldown.

**Приёмка.** CI зелёный. В PR у каждого нового теста указано, какой откат продового кода его роняет.

### H20 — CLEANUP: зависимости, мёртвый код, язык (low) ← H17, H18
1. Бинарник:
   - удалить `tor-error`, `serde`, `serde_json`, `indexmap`, `time`, `thiserror`, `getrandom` — ноль упоминаний в `src`, `benches`, `tests` на 2026-11-17; сначала проверить, что ни одна не включает фичу в графе;
   - `bridge-fetcher`, `bridge-line`, `tempfile` перенести в dev-deps;
   - `arti-wrapper` оставить, только если он нужен для фичи;
   - санкции записать в ci_planner (`SANCTIONED_DEPENDENCY_REMOVALS`).
2. Server:
   - неиспользуемая фича `test-seams` (`Cargo.toml:30`);
   - `bridge-line`, `bridge-store`, `time`, `tracing-subscriber` → dev-deps, если они нужны только тестам (`Cargo.toml:36,37,45,51`);
   - `pub struct Upstream` в приватном модуле (`server/server/egress/upstream.rs:48`).
3. Устаревшие описания и ссылки: `runtime/Cargo.toml:9`, `server/Cargo.toml:9`, `runtime/lib.rs:1-6`, `apps/sdk/Cargo.toml:31-35`, `apps/socks5-proxy/src/main.rs:12-13` (вместе с `#[allow(dead_code)]`), `runtime/tor/tor_watchdog/tor_watchdog_tests.rs:6-7`, `apps/sdk/crates/server/README.md:48`.
4. Оставшиеся русские сообщения ошибок и логов в библиотеках перевести на английский (D-H3).

**Приёмка.** CI зелёный, планировщик подтверждает удаления.

### H21 — BIN-ON-FACADE: бинарник на фасаде (low) ← H18, H20; D-H5
`apps/socks5-proxy/Cargo.toml` зависит от `tor-socks5` (фичи `full` и `pt`) вместо внутренних крейтов, импорты идут через фасад. Что так не выражается — список с причинами в PR. Санкции планировщика.

**Приёмка.** CI зелёный; прямые зависимости бинарника на крейты SDK остаются только обоснованные.

### H22 — VERIFY: живая проверка (← все)
Release-бинарник (`capc 10 cargo build --release -p socks5-proxy`), временный каталог с копией конфига мостов владельца; каталог удаляется после проверки. Проверяется:
- бутстрап через мосты;
- собственный .onion с правильным адресом;
- `onion remove` во время бутстрапа → сервис не публикуется;
- Ctrl-C во время старта → код 0;
- Ctrl+Break в работе → код 0;
- INFO-логи продуктовых крейтов.

Примеры SDK только собираются в CI; запускать их локально — только с разрешения владельца.

## 5. Правила исполнения

- **Исполнитель:** rush в отдельном worktree `worktrees/<slug>` (/wrush), ветка `<slug>-2026MMDD`. Дальше: PR → `gh pr checks --watch -i 300` в фоне → `gh pr merge --merge` → удаление ветки и worktree только после состояния MERGED.
- **Локально** — только `cargo check`, `cargo clippy`, `cargo fmt`, `cargo metadata`, скрипты репозитория и тесты планировщика. Свои новые тесты одного крейта — только `capc 10 cargo test -p <crate> <filter>`. Остальное делает CI. Локальный Rust 1.97, в CI 1.100: новые clippy-линты всплывают только в CI.
- **Предположения** из §4 исполнитель проверяет по коду в начале задачи. Не подтвердилось — пункт закрывается с записью в PR.
- **Конфликты:** задача, которая стартует после влития соседней, делает rebase на main. Задачи одной волны, затрагивающие один файл, отмечены в §3.
- **Частные пути машины** в репозиторий не попадают; `docs/upstream/` и `docs/checkpoints/` не коммитятся.
- **Статус задач:** этот план обновляется в PR каждой задачи (строка «Статус» вверху).
