# SDK: покрытие всех возможностей — план

- **Дата:** 2026-11-15
- **Статус: в работе.** Сделано: SDK-1 (этот план, PR #92), SDK-2 (README фасада, PR #93), SDK-0 (разрезы циклов, PR #94), SDK-12 (пользователи как API, PR #95), SDK-4 (ключи onion как API), SDK-7 (писатель здоровья мостов и наблюдение за guard-событиями), SDK-9 (Tor-клиент как API), SDK-8 (менеджер мостов как API). Ревизия 2026-11-15 сверила план с кодом и изменила раскладку и порядок работ: что нашлось — в §4 «Ревизия», что изменилось — в §5 и §7. Решения владельца собраны в §9: 2026-11-15 решены D1, D3 и D5, добавлено правило R11; D2 и D4 остаются рекомендациями.
- **Основа:** [sdk-package-design.md](../project/sdk-package-design.md) (решение 2026-11-11: библиотеки не сливаются, наружу идёт фасад `tor-socks5`, `publish = false`, git-зависимость, Tor-фичи — с patch-kit). Этот план ничего в нём не отменяет, а отвечает на вопрос, чем фасад пока не покрывает бинарник.
- **Числа:** строки без тестов, `wc -l` по `apps/socks5-proxy/src` и `packages/*` на 2026-11-15 (main `9a36602`; после SDK-0 часть чисел сдвинулась, например `bridge_warmer.rs` 760 → 240); связи — по `crate::…` и `super::…` в нетестовых файлах. Каждую связь из §4 заново подтверждает задача, которая её режет.

## 1. Цель, критерий приёмки, не-цели

**Цель.** Всё, что оператор делает бинарником `tor-socks5`, встраиваемое приложение делает кодом: поднять прокси-сервер, поднять onion-сервисы, вести пул мостов, управлять ключами и пользователями.

**Критерий приёмки** (проверяется CI, не локально):

1. Для каждой строки таблицы §2 с целью «вынести» есть публичный модуль фасада за фичей, и `apps/sdk/tests/surface.rs` его проверяет.
2. Бинарник — тонкий клиент этих крейтов: в нём остаются разбор командной строки, справка, служба ОС, «ангел», `main` и процессная инициализация.
3. Поведение бинарника не меняется: те же команды, формат конфига и ключей на диске, строки логов, которые проверяют тесты. Тесты переезжают вместе с кодом.
4. `android-ffi` перестаёт дублировать загрузку, верификатор мостов и egress (§7, SDK-13; по решению D3); крейт при этом переезжает в `apps/android-ffi` (R11).

**Не-цели.** Публикация на crates.io (вендорный гейт §4 старого дизайна остаётся); новые возможности; заморозка semver; GUI; служба ОС и `clap` в SDK.

## 2. Что покрыто сегодня и что нет

| Возможность | Где код | В SDK | Цель |
|---|---|---|---|
| SOCKS5-протокол, ACL, пароли, пулы маршрутов, схема конфига (`guard_spread` и др.) | `packages/{socks5-proto,proxy-config,auth}` | да | без изменений |
| Здоровье мостов: хранилище, проба, ядро проверки | `packages/bridge-{store,probe,verify-core}` | да | без изменений |
| Tor-клиент: `TorTunnel`, `Settings`, pre/post-эндпоинты, onion-клиент | `packages/arti-wrapper` | да | без изменений |
| Сбор мостов, DNS-сервер | `packages/{bridge-fetcher,dns-server}` | да (`fetch`, `dns`) | без изменений |
| Адрес onion и vanity-поиск | `commands/onion/{address,vanity}` — 316 + 612 | **нет** | `onion` (без Tor) |
| Ключи и идентичности сервисов (new/list/show/export/import/remove) | `tor-socks5-onion` (`keys`); в бинарнике остались разбор аргументов, подтверждения и печать | да (SDK-4) | сделано |
| Хостинг onion-сервисов: гейт старта, лимиты, статусы | `commands/onion/service/*` — 1356 | **нет** | `onion` + `host` |
| Подготовка Tor из конфига: `Settings`, пробинг, seed, PT | `tor/tor_setup` (+ `owner_settings`), `fetch/seed` — 993 + 217 + 102 | **нет** | `runtime` |
| Наблюдение за guard-событиями (`ObservationSink`) | `tor/arti_observability` — 453 | **нет** | `runtime` |
| Watchdog, здоровье соединения | `tor/{tor_watchdog,conn_health}` — 1327 + 614 | **нет** | `runtime` |
| Tor-клиенты владельцев pre-пула, запуск производителей мостов | `tor/tor_watchdog/owners/*`, `fetch/bridge_producers` — 2264 + 94; подмодули `server` (§4, ревизия) | **нет** | `server` |
| Менеджер мостов: запись здоровья, верификатор, прогрев, пул кандидатов, обслуживание, слияние | `bridges/*`, `fetch/fetch_merge` — ≈ 5000 + 706 | **нет** | `runtime` |
| Сервер: listen, egress (pre/post/upstream/Tor-ветка), DNS-проводка, запуск, остановка | `server/*` — ≈ 3400 | **нет** | `server` |
| Команды `users` и `config migrate` | `packages/auth` (`Registry`), `packages/proxy-config` (`migrate_config`); в бинарнике остались запрос пароля и печать | да (SDK-12, PR #95) | сделано |
| `service install/uninstall/start/stop`, `help`, `--angel`, `clap`-разбор | `commands/{service,help_cmd,angel,cli}` | **нет, и не нужно** | остаётся в бинарнике |

Итог: библиотеки — это «кирпичи» (≈ 29 тыс. строк в `packages/` без `android-ffi`), а всё «живое» (≈ 18 тыс. строк: сервер, мосты, Tor-рантайм, onion-хостинг) — в бинарнике и доступно только через процесс. `android-ffi` (≈ 6,5 тыс. строк) отдельно держит свои копии загрузки, верификатора и egress; `guard_spread` туда не проброшен.

## 3. Ограничения репозитория, которые определяют раскладку

- `scripts/check-dir-entries.sh`: не больше 7 записей (файлы + подкаталоги) на каталог. Исключения — только базовые значения: корень 16 и `packages/` 11; они **не могут расти**. `docs/project/` уже на 7.
- `scripts/check-line-limit.sh`: не больше 1000 строк на Rust-файл. Близко к пределу: `tor_setup.rs` 993, `server.rs` 914, `bridge_verifier.rs` 899, `tor_watchdog_runtime.rs` 835. Перенос «как есть» проходит, но любое добавление API в эти файлы требует их предварительного разбиения.
- Тесты и сборки локально не запускаются; гейт — GitHub CI, план affected-режима строит `scripts/testing/ci_planner.py`. Для каждого нового каталога крейта нужно проверить, что планировщик и `scripts/publishable-crates.sh` / `check-publish-guard.sh` его знают: SDK-3 проверяет раскладку, `members` и publish-guard, SDK-6 — пути в планировщике и в скриптах реального канала (§4, ревизия, п. 9).

## 4. Находки: связи внутри бинарника

В `main.rs` модули подключены плоско через `#[path]`, поэтому граф читается по `crate::<модуль>`.

**Клубок модулей.** `tor_setup`, `bridge_store_writer`, `bridge_verifier`, `bridge_warmer`, `tor_watchdog` ссылались друг на друга. Выносить их по одному нельзя: библиотека не может ссылаться на модуль бинарника. Причины оказались не там, где предполагал первый набросок этого плана (который считал причиной вызов `update_health_and_prune`: он вызывается из самой `tor_setup`, так что вынос этой функции ничего не разрезал):

- `bridge_store_writer` и `tor_setup` брали у `bridge_verifier` не верификацию, а универсальные помощники фоновых блокирующих задач (`run_fallible_blocking`, `run_tracked_blocking`, `spawn_blocking_with_failure`, `Delivery`, `WorkerFailures`, `TestWorkers`, `join_blocking_workers`, `AdmissionWorkers`). Они лежали в `bridge_maintenance/workers.rs` и пробрасывались через `bridge_verifier` реэкспортом; тем же путём ими пользовались `commands/onion/service` и `owners/producers`.
- `tor_watchdog` брал чистое ранжирование (`select_top_n`, `candidates_with_health`, `Health`) из `bridge_warmer`, а `bridge_warmer` брал `TorHandle` из `tor_watchdog`.
- `conn_health` брал типы `ConnStage` / `ConnErrorKind` из `server`, а `bridge_maintenance` — чистую `compute_deficit` оттуда же.

**Три узких разреза решают это без трейтов и без смены поведения** (сделаны внутри бинарника, SDK-0, до выноса):

1. `bridge_maintenance/workers.rs` стал модулем верхнего уровня `crate::workers`; реэкспорт через `bridge_verifier` убран, все вызовы идут напрямую. `bridge_store_writer`, `tor_setup`, онион-хостинг и `owners` больше не зависят от верификатора.
2. Ранжирование (`Health`, `select_top_n`, `candidates_with_health`) вынесено из `bridge_warmer` в листовой `bridge_maintenance/bridge_rank.rs`: `tor_watchdog` и `bridge_warmer` ссылаются на него, а не друг на друга.
3. `ConnStage` и `ConnErrorKind` переехали в `conn_health`, `compute_deficit` — в `bridge_maintenance` (единственный потребитель вне тестов).

Порядок зависимостей снизу вверх после разрезов (это не порядок PR, см. ревизию ниже): `workers`, `bridge_rank`, `seed`, `arti_observability` → `bridge_store_writer` → `tor_setup` → `tor_watchdog` + `TorHandle`, `conn_health` → `bridge_verifier`, `candidate_pool`, `bridge_warmer` → `fetch_merge`, `bridge_maintenance` → `server`. Хостинг onion зависит от `TorHandle` и `workers`, поэтому стоит над рантаймом.

**Ревизия 2026-11-15: что показала сверка с кодом.** Первая версия плана раскладывала модули по именам каталогов. Проверка по `#[path]`, `crate::…` и `super::…` дала девять поправок.

1. **Дерево `server` шире каталога `server/`.** `server.rs` подключает как свои подмодули `tor/tor_watchdog/owners/{mod,producers,handlers,global_init}.rs`, `fetch/bridge_producers.rs` и `server/egress/{pre_pool,tor_branch}.rs`. `handlers.rs` и `bridge_producers.rs` начинаются с `use super::*;`, в `handlers.rs` лежит `accept_loop`, а `global_init.rs` ставит подписчик логов и крипто-провайдер и ведёт порядок старта. Ни один модуль рантайма на них не ссылается. Это часть сервера (L3), а не рантайма.
2. **Рантайм ссылается вверх в одном месте:** `route::pre_endpoint` в `tor_setup.rs` и `bridge_maintenance.rs`. Это одна строка над `Socks5PreEndpoint::from_pool_member`. Ещё есть ссылки в doc-комментариях на `crate::server::run_server` и `crate::bridges_cmd::cmd_bridges`.
3. **Модули рантайма не выносятся по одному.** Причин четыре:
   - остался цикл: `tor_watchdog_runtime` зовёт `bridge_maintenance::pre_channel_ready`, а `bridge_maintenance`, `bridge_verifier` и `bridge_warmer` берут `TorHandle` / `TorHealth` у watchdog;
   - `tor_setup` зовёт `bridge_store_writer::apply` и берёт `ObservationSink`, то есть подготовка Tor зависит от писателя здоровья, а не наоборот;
   - тесты связаны поперёк: тесты `workers` зовут `bridge_maintenance::load_config_off_worker`, тесты `arti_observability` — `tor_watchdog::BridgeRefresh`, `ts19_tests` — `tor_setup` и `bridge_verifier`;
   - `test_seams` — модуль `#[cfg(test)]` в корне крейта, и его зовёт нетестовый код `bridge_store_writer`, `bridge_maintenance`, `bridge_verifier`, `bridge_warmer`, `candidate_pool`, `fetch_merge`, `tor_watchdog_runtime`. В крейте-зависимости `cfg(test)` выключен, так что на каждой промежуточной границе понадобились бы фича для швов и временный `pub`.

   Вывод: рантайм переезжает одним PR (§7, SDK-6).
4. **Перенос не требует правки путей внутри.** Модули бинарника подключены плоско. Если `lib.rs` нового крейта подключит те же файлы под теми же именами, а `config` оставит реэкспортом `proxy_config`, все `crate::x` в перенесённых файлах останутся верными. Меняются только потребители по другую сторону границы и видимость того, что они берут.
5. **Что берут через границу рантайма** (нетестовый код):
   - сервер: `tor_setup::{restricted_owner_settings, validate_owner_routes, update_health_and_prune, build_tor_settings}`, `tor_watchdog::{TorHandle, classify_and_record}` и другое из `tor_watchdog`, `conn_health`, `arti_observability::ObservationSink`, `bridge_store_writer::{StoreWriter, init_global, close_global}`, `bridge_maintenance::preferred_missing`, `workers`;
   - `bridges fetch`: `candidate_pool::CandidatePool`, `fetch_merge::{drain_pool, refresh_candidate_pool}`, `tor_setup::build_tor_settings`;
   - onion: `tor_setup::arti_base_dir` (`store.rs`), `tor_watchdog::TorHandle` и `workers::run_fallible_blocking` (`service/mod.rs`).

   Тесты дерева сервера берут тестовые помощники рантайма: `test_seams::{ParkedGate, Site, HANG_GUARD, FORBID_PRODUCER}` и `workers::TestWorkers` (`owners/producers.rs`, `bridge_producers_tests.rs`). Для них нужна фича (R10).
6. **Ключи onion не должны зависеть от рантайма.** `store.rs` берёт у `tor_setup` только `arti_base_dir`, чистую функцию «каталог конфига → `arti-data`». Каталог приходит в API ключей аргументом (R7).
7. **Vanity печатает.** `vanity.rs` пишет прогресс через `eprintln!` и обрабатывает Ctrl-C (`search_for_cli`). В библиотеку идёт ядро поиска с обратным вызовом прогресса и флагом отмены, печать остаётся в бинарнике.
8. **Глобальное состояние в переносимом коде** (перечень; судьба — D5): `WRITER` (`bridge_store_writer`), `BLOCKING_WORKERS` (`workers`), `VERIFY_LOCK` (`bridge_verifier`), `SAVE_SEQ` (`candidate_pool`), `RETAINED` в `owners/{mod,producers,handlers,global_init}`, `SETTINGS` (`global_init`), `QUARANTINE` (`owners/storage`), установка крипто-провайдера в `global_init` и `producers`.
9. **CI знает пути бинарника.** В `scripts/testing/ci_planner.py` записаны буквальные пути (`apps/socks5-proxy/src/bridges/bridge_maintenance.rs`, `…/real_channel_tests.rs`) и правило сегмента `tor` по префиксу `apps/socks5-proxy/`. На те же пути опираются `real-tor-channel.sh`, `real-tor-mutations.sh` и тесты планировщика. Без их правки перенос рантайма либо уронит задание `plan`, либо перестанет выбирать задание с реальным каналом Tor; какой из двух исходов наступит, не проверялось. Крейт без Tor (SDK-3) этого не поймает.

`route::pre_endpoint` — одна строка поверх `Socks5PreEndpoint::from_pool_member`, `reject_unsupported_pool` — проверка конфига; первый нужен ниже `server` и убирается из рантайма отдельным коммитом перед его переносом (SDK-6), второй остаётся в сервере.

**Процессное состояние.** 91 вхождение `process::exit`, `println!`/`eprintln!`, `rpassword`, `clap`, `tracing_subscriber` и статиков в 18 файлах (часть — в командах, которые остаются в бинарнике). В библиотеки они не едут (правила R1, R5): подписчик логов, установка крипто-провайдера, привязка дочерних процессов, восстановление при старте и ANSI-режим консоли остаются в бинарнике или в явном модуле `process` с пометкой «вызывать один раз».

## 5. Целевая раскладка

```
L0  существующие packages/*  (без изменений)
L1  tor-socks5-runtime   tor_setup (+ owner_settings), seed, observability, watchdog + TorHandle,
                         conn_health, мосты целиком, fetch_merge, workers
L2  tor-socks5-onion     address, vanity           (без Tor)
                         + keys  (feature, tor-keymgr/tor-hscrypto; каталог Arti приходит аргументом)
                         + host  (feature, зависит от runtime: TorHandle, workers)
L3  tor-socks5-server    listen, egress, owners (Tor-клиенты pre-пула), bridge_producers,
                         запуск, остановка, DNS-проводка
бинарник                 clap, help, служба ОС, angel, main, процессная инициализация,
                         разбор аргументов `bridges fetch`
```

Три новых крейта, не десять: клубок §4 нельзя разрезать по границам крейтов без трейтов, а трейты ради одной сборки — лишняя поверхность. Отвергнутый вариант — отдельные `tor` / `bridges` / `fetch`: из-за связей tor_setup ↔ мосты он потребовал бы обратных вызовов через трейты.

**Где лежат каталоги (решение D1, решено 2026-11-15).** `packages/` заморожен на 11, корень на 16, поэтому ни `packages/<новый>`, ни корневой `sdk/` не пройдут `check-dir-entries`. Выбран вариант A: новые крейты в `apps/sdk/crates/{runtime,onion,server}` — `apps/sdk` растёт с 4 до 5 записей, у `crates/` запас до 7; библиотеки лежат рядом с фасадом, которому принадлежат; `packages/` не трогаем. В корневом `Cargo.toml` в `members` добавляется одна строка `"apps/sdk/crates/*"` — глоб `apps/*` внутрь `apps/sdk` не заходит (как `packages/*` не покрывает `proxy-config/client-acl`); строку создаёт SDK-3, следующим крейтам она уже не нужна. Отвергнутые варианты: B — вложение в существующие каталоги по образцу `proxy-config/{client-acl,route-pool}` (имена вводят в заблуждение: хостинг onion внутри `proxy-config`); C — перегруппировка `packages/` (переименование крейтов, правка путей, CI и документации, места хватило бы не на все три крейта).

## 6. Стиль runtime-API (общий для всех выносов)

- **R1. Без глобального состояния.** Ни `static` с `Mutex`/`OnceLock`, ни установки подписчика логов, ни `rustls::install_default` внутри библиотек. Всё процессное — явные функции, которые вызывает приложение. Для нового кода правило действует сразу; статики, которые приезжают с переносом, перечислены в §4 (ревизия, п. 8), их судьбу фиксирует D5.
- **R2. Конфиг на вход, ручка на выход.** `Server::builder(config)…start().await? -> ServerHandle`; то же для хостинга onion и менеджера мостов. Остановка — явный `handle.shutdown().await`; `Drop` только отменяет токен и не блокируется (никакой async-работы в `Drop`).
- **R3. Владение задачами.** Каждая запущенная задача принадлежит ручке (`JoinSet`/`TaskTracker`), отмена идёт через `CancellationToken`; брошенных `JoinHandle` нет.
- **R4. Статус.** Текущее состояние — `tokio::sync::watch`, события — ограниченный `broadcast` с документированной потерей при отставании. Неограниченных каналов нет.
- **R5. Тишина.** Никакого `println!`, `process::exit`, `clap`, `rpassword` в библиотеках; запрос пароля — трейт, как уже сделан `RpasswordPrompt` в `users_cli`.
- **R6. Логи.** Только события `tracing`. Слой наблюдения за guard-событиями отдаётся как `observation_layer()` для подписчика приложения.
- **R7. Пути и время.** Каталог состояния и все пути приходят из конфига; библиотека не читает текущий каталог и окружение, кроме документированных переменных.
- **R8. Ошибки.** Там, где вызывающий должен различать причины (неверный конфиг, порт занят, хранилище ключей заблокировано, мосты закончились), — типизированный `enum`; остальное — `anyhow` внутри и в документации API.
- **R9. Поверхность.** `pub` — только конфиг, ручка, статусы и события; всё остальное `pub(crate)`. Фасад не публикуется, так что можно уточнять до первого потребителя.
- **R10. Тестовые швы.** `#[cfg(test)]` не виден из другого крейта. Шов или тестовый помощник, который нужен тестам другого крейта, закрывается `#[cfg(any(test, feature = "test-seams"))]`. Фичу включают только `dev-dependencies` потребителя; в `default`, `full` и в фасад она не входит.
- **R11. Направление зависимостей.** `packages/*` не зависят от `apps/*` (сейчас выполняется). Продукт, который собирается артефактом (cdylib), а не библиотекой-«кирпичом», в `packages/` не живёт: SDK-13 переносит `android-ffi` в `apps/android-ffi`; `packages/` сжимается с 11 до 10 записей, baseline в `check-dir-entries.sh` понижается тем же PR; `members` правки не требует — новый путь накрывается существующим глобом `apps/*`.

## 7. Порядок работ

Каждый шаг — отдельный PR (ветка → PR → зелёный CI → merge). Работа бывает трёх видов, и в одном PR они не смешиваются:

- **разрез** — правка внутри бинарника, которая убирает связь, мешающую переносу;
- **перенос** — файлы переезжают как есть, меняются только пути у потребителей и видимость; приёмка — зелёный CI;
- **API** — поверх перенесённого кода делается поверхность по R1–R10 (конфиг на вход, ручка на выход, статусы). До этого шага то, что нужно потребителям, открыто как `#[doc(hidden)] pub`.

Модуль фасада и проверка в `surface.rs` добавляются в PR, который делает API, а не перенос.

| Задача | Вид | Суть | Зависит от | Состояние |
|---|---|---|---|---|
| SDK-1 | — | этот документ | — | сделано, PR #92 |
| SDK-2 | — | README фасада: `guard_spread`, честный список «чего нет»; assert в `surface.rs` | — | сделано, PR #93 |
| SDK-0 | разрез | три разреза §4 (`workers`, `bridge_rank`, `ConnStage` / `ConnErrorKind` / `compute_deficit`) | SDK-1 | сделано, PR #94 |
| SDK-12 | API | пользователи: `auth::Registry` без запроса пароля и печати | SDK-1 | сделано, PR #95 |
| RT-0 | разрез | `WRITER` в `bridge_store_writer` — сбрасываемый слот: `close_global()` очищает ячейку, повторный `init_global` запускает нового писателя | — | сделано |
| SDK-3 | перенос + API | крейт `tor-socks5-onion`: адрес и ядро vanity без Tor; первый новый крейт — добавляет в корневой `members` строку `"apps/sdk/crates/*"` | — | |
| SDK-6 | разрез + перенос | крейт `tor-socks5-runtime` одним PR: `tor/` без `owners`, `bridges/`, `fetch/{seed, pt_binary_override, fetch_merge}`, `workers`, `test_seams`, `ts19_tests`. Перед переносом отдельным коммитом убрать `route::pre_endpoint` из рантайма. В том же PR: фича `test-seams`, правка `ci_planner.py` и скриптов реального канала | RT-0 | |
| SDK-9 | API | Tor-клиент: подготовка из конфига, точка входа PT для встраивающего хоста, поверхность `TorHandle`, статус watchdog и `conn_health`; зависимость от patch-kit в документации | SDK-6 | сделано |
| SDK-7 | API | писатель здоровья мостов как ручка; `observation_layer()` для подписчика приложения | SDK-6 | сделано |
| SDK-8 | API | менеджер мостов: ручка, отмена, логика `bridges fetch` как функция | SDK-6, SDK-7, SDK-9 | сделано |
| SDK-4 | перенос + API | `onion` + `keys`: хранилище, идентичности, логика команд; каталог Arti аргументом | SDK-3 | сделано |
| SDK-5 | перенос + API | `onion` + `host`: гейт старта, лимиты, статусы | SDK-4, SDK-9 | |
| SDK-10 | разрез + перенос | крейт `tor-socks5-server`. Сначала PR-разрез: процессная инициализация из `startup`, `shutdown` и `global_init` отделяется от `run_server`. Затем перенос дерева `server` целиком, с `owners`, `bridge_producers` и `egress` | SDK-5, SDK-6, SDK-9 | |
| SDK-11 | API | `Server::builder(config)…start() -> ServerHandle`; часть исполнения D5: второй одновременный `start()` возвращает типизированную ошибку `AlreadyRunning`, в приёмке тест «старт → стоп → старт» | SDK-8, SDK-10 | |
| SDK-13 | перенос | `android-ffi` на общий рантайм: загрузка, верификатор мостов, egress, `guard_spread`; крейт переезжает в `apps/android-ffi` (R11), baseline `packages` в `check-dir-entries.sh` понижается 11 → 10 тем же PR | SDK-11 | |
| SDK-14 | — | примеры, матрица фич в CI, итог в README фасада | SDK-11 | |

SDK-3 и SDK-6 сделаны (D1 решено, RT-0 влит). После SDK-6 ветка onion (SDK-4, SDK-5) и ветка API рантайма (SDK-7, SDK-9, SDK-8) идут параллельно; SDK-5 и SDK-8 ждут SDK-9.

Что ревизия изменила в порядке: SDK-6, SDK-7, SDK-8 и SDK-9 раньше были четырьмя переносами частей рантайма, теперь перенос один (SDK-6), а остальные три делают API. SDK-10 раньше выносил `egress` и `owners` в рантайм, теперь это перенос сервера. Работа по `android-ffi` убрана из SDK-6 и SDK-8 и вся собрана в SDK-13.

Фичи фасада (новые, поверх §3 старого дизайна): `onion` (адрес, vanity — без Tor, в `default` не входит), `onion-keys` (ключи и идентичности), существующая `onion-service` расширяется хостингом, `runtime`, `server`; `full` включает всё, кроме `test-seams`. Фасад не выпущен, так что переопределять смысл `onion-service` можно без поломки потребителей.

## 8. Риски

- **Лимит 1000 строк.** Модули у предела перед добавлением API разбиваются отдельным коммитом PR, без правок логики.
- **Один крупный перенос рантайма.** Около 9,5 тыс. строк в файлах кода и 5,5 тыс. строк в отдельных тестовых файлах одним PR. Дифф при этом мал: файлы переименовываются без правки содержимого (§4, ревизия, п. 4), меняются `lib.rs`, манифесты и потребители. Ревью идёт по CI и по списку изменённых строк вне переименований.
- **Каскад видимости.** Всё, что сервер, `bridges fetch` и onion берут у рантайма, становится `pub`, а вместе с этим и типы в сигнатурах. До шага API это `#[doc(hidden)] pub`; шаг API сужает поверхность до R9.
- **Глобальное состояние.** Статики из §4 (ревизия, п. 8) переезжают как есть по D5; контракт «один живой экземпляр на процесс, последовательный перезапуск работает» — в документации API. RT-0 исполнен (`WRITER` — сбрасываемый слот, перезапуск протестирован); до SDK-11 второй одновременный запуск сервера ошибкой не отмечается.
- **Android.** У `android-ffi` свой запуск PT (`pt_reap`) и нет busybox-диспетчеризации бинарника. Рантайм должен брать запуск PT через шов, иначе SDK-13 не сойдётся; это проверяется в SDK-9.
- **CI и скрипты.** `ci_planner.py` и скрипты реального канала содержат пути бинарника (§4, ревизия, п. 9); правятся в PR переноса рантайма. `check-publish-guard.sh` читает все `Cargo.toml` репозитория, так что каждому новому крейту нужен `publish = false`.
- **Процессное состояние** (§4): перечень `static` и вызовов `process::*` делается в задаче каждого переноса до переноса, а не после.

## 9. Решения владельца

- **D1. Каталог новых крейтов — решено (2026-11-15): вариант A,** новые крейты в `apps/sdk/crates/{runtime,onion,server}`; обоснование и отвергнутые варианты — §5.
- **D2. Три крейта (`runtime`, `onion`, `server`)** вместо более дробной раскладки — рекомендация: три, причины в §5.
- **D3. Входит ли `android-ffi` (SDK-13) — решено: да,** отдельным шагом после SDK-11. Это параллельный движок (~2,5 тыс. строк `engine/` без тестов) со своими статиками (`ENGINE`, `ENGINE_GENERATION`, `STATUS`) и первый настоящий потребитель серверного API и контракта перезапуска; гейт — задание `android` в CI.
- **D4. `onion` не в `default`:** рекомендация — не добавлять; `default` остаётся без Tor и без нового кода по умолчанию.
- **D5. Глобальное состояние рантайма и сервера — решено (2026-11-15): вариант A с проверяемым контрактом** (§4, ревизия, п. 8). Статики трёх видов: (1) процессные по природе — `SAVE_SEQ`, `VERIFY_LOCK`, `BLOCKING_WORKERS` — остаются; (2) слоты экземпляра `Mutex<Option<Arc<…>>>` в `tor_watchdog/owners/*` — ставятся при старте и снимаются при остановке, перезапуск переживают, два экземпляра одновременно — нет; (3) `WRITER` в `bridge_store_writer` — исполнено (RT-0): сбрасываемый слот `Mutex<Slot>`, после `close_global()` повторный `init_global` запускает нового писателя, перезапуск протестирован (`bridge_store_writer_tests/external_cli_tests.rs`). Контракт API: «один живой экземпляр на процесс, последовательный перезапуск работает». Исполнение: RT-0 исполнен (сбрасываемый слот, до SDK-6); в SDK-11 второй одновременный `start()` возвращает `AlreadyRunning`, тест «старт → стоп → старт» — в приёмке. Вариант B (состояние во владении ручки) отложен до появления потребителя с двумя экземплярами в процессе.
