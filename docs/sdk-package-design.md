# tor-socks5 — цельный пакет: дизайн (blueprint)

- **Дата:** 2026-09-20
- **Статус:** blueprint — это РЕШЕНИЕ (блюпринт для последующих работ), а не обзор; реализация разбивается на отдельные задачи.
- **Предшествующее исследование:** [docs/crates-io-publish-research-2026-09-19.md](crates-io-publish-research-2026-09-19.md), далее «research». Ссылки на его секции: §1 ([patch.crates-io] при публикации), §2 (апстрим-статусы фиксов), §4 (API-поверхности крейтов), §5 (граф зависимостей), §6 (android-ffi вне crates.io). Этот документ опирается на research и не переписывает его.
- **Оговорка о свежести:** факты о занятости имён на crates.io проверены **2026-09-20**: имя `tor-socks5` СВОБОДНО (как и `tor-socks5-sdk`, `torsocks5`); `dns-server` ЗАНЯТО; свободны также `persist-lock`, `bridge-verify-core`, `tor-socks5-auth`, `bridge-probe`, `bridge-store`, `tor-socks5-config`, `tor-socks5-proto`.
- **Решение пользователя (2026-09-20, пересмотру не подлежит):** ничего не публиковать на crates.io прямо сейчас; цель — публикация ОДНИМ ЦЕЛЬНЫМ ПАКЕТОМ (один крейт, не набор из 7+ крейтов), первая версия 0.1.0. Апстрим-патчи в эту задачу не входят.
- **Параллельная работа (SDK-03):** крейт `dns-server` переименовывается в **`tor-socks5-dns`**. Этот документ не зависит от того, успело переименование: ниже `tor-socks5-dns` — целевое имя, текущее `dns-server` указано в скобках.
- **Числа:** все объёмы пересчитаны заново по `git ls-files` / `wc -l` / `grep` этого worktree 2026-09-20 (методика — Приложение A).

---

## 1. Имя и форма

Имя единственного публикуемого крейта — **`tor-socks5`**:

- имя свободно на crates.io (проверено 2026-09-20);
- совпадает с именем репозитория и с `repository`/`homepage` в `[workspace.package]` (Cargo.toml:17–18);
- точно описывает содержимое (SOCKS5-прокси на Tor с самоуправляемыми мостами) и не требует ни суффикса `-sdk`, ни префиксов.

Сравнение трёх вариантов формы.

### (а) Фасад-крейт, зависящий от 7 внутренних — НЕ решает

- crates.io требует, чтобы **все** зависимости публикуемого крейта были опубликованы. Фасад, зависящий от `persist-lock`, `bridge-verify-core`, `tor-socks5-auth`, `bridge-probe`, `bridge-store`, `tor-socks5-config`, `tor-socks5-proto`, вынужден издать их все раньше себя.
- Итог: имён на crates.io становится **8, а не 1** — публикация «одним цельным пакетом» не состоялась по определению.
- Семь «красивых» имён сегодня свободны, но это не помогает: фасад не избавляет **ни от публикации всех восьми**, ни от **пожизненной semver-синхронизации** между ними.
- Цена синхронизации конкретна: любой внутренний фикс = 8 релизов одной пачкой; расхождение версий крейтов одной семьи = неразрешимые diamond-конфликты у потребителя; dep-факты research §5 (9 внутренних path-зависимостей только у apps/socks5-proxy) показывают, насколько плотна эта семья.
- И даже пройдя через это, 7 из 8 останутся vendor-clean, а тор-часть графа всё равно упрётся в вендорный гейт (§4) — фасад не приближает его открытие ни на день.

### (б) Физическое слияние библиотечных крейтов в один крейт с модулями — база рекомендации

- 10 библиотечных пакетов воркспейса превращаются в 10 модулей одного крейта `tor-socks5` (карта — §2).
- Один манифест, одна точка публикации, один semver-поток, один README, один `cargo add` / `cargo install`.
- Граф внутренних зависимостей (research §5: чистый 4-уровневый DAG без циклов) никуда не девается, но перестаёт быть графом **версий** и становится графом модулей, проверяемым компилятором за одну сборку.
- Гигиенический блокер research §7 (отсутствие `version` у path-зависимостей) уже закрыт (коммит ae8cd2f: у всех внутренних path-зависимостей проставлено `version = "0.1.0"`) — для формы (б) он и вовсе исчезает: path-зависимостей между модулями одного крейта не бывает.

### (в) Гибрид — рассматривается честно и поглощается рекомендацией

- **(в1) Слить только 7 vendor-clean** (persist-lock, bridge-verify-core, auth, bridge-probe, bridge-store, proxy-config, socks5-proto), а tor-стек (`arti-wrapper`, `bridge-fetcher`, dns-server→`tor-socks5-dns`) держать отдельными крейтами до открытия вендорного гейта.
  - Минус: два крейта вместо одного, и публиковать до гейта всё равно нельзя ни один (§4); после гейта тор-часть была бы вторым именем — возвращаемся к «несколько имён» в миниатюре; плюс двойная работа по импортам при втором слиянии.
- **(в2) Слить всё физически, но tor/dns спрятать за фичами** — это и есть итоговая форма.
- **Итоговая рекомендация — «(б) с фичами».** Физически сливаем все 10 библиотечных крейтов **сразу**; гибридную часть обеспечивает исключительно фича-матрица §3: фичи `tor`/`dns`/`fetch` объявлены с первого коммита слияния, но выключены в default, а публикация до открытия гейта не производится вовсе (§4, вариант ii).
- Отличие от чистого (б) только в том, что «цельность» публикации отложена вендорным гейтом, а не формой репозитория: с первого дня существует ровно один библиотечный крейт.

### Честные минусы (б)

- **Теряется независимое переиспользование `persist-lock`** — самого домен-агностичного крейта воркспейса (research §4: «arguably the most portable crate in the whole workspace precisely because it has no domain coupling at all»). Внутри единого крейта он становится `pub(crate)`-модулем (§2): внешние потребители файловых локов без остального домена остаются за бортом. Осознанная жертва.
- **Растёт юнит компиляции:** один rlib на ~43,5 тыс. строк библиотечного кода вместо десяти маленьких; параллелизм инкрементальной сборки внутри крейта ниже, чем между крейтами.
- **Границы подсистем держатся дисциплиной модулей** (`mod`-видимость, `pub(crate)`), а не границами крейтов, которые раньше enforced'ились компилятором автоматически: «из auth нельзя дотянуться до fetch» больше не проверяется даром — это становится code-review-правилом.
- **pub-поверхность единого крейта по умолчанию «видит» всё:** нужна явная дисциплина `pub`/`pub(crate)` по каждому модулю (решения — в таблице §2), иначе единый крейт вывернет все внутренности наружу.

### Сводка сравнения

| Критерий | (а) фасад | (б) слияние | (в) гибрид |
|---|---|---|---|
| Имён на crates.io | 8 | **1** | 1 (при в2) / 2+ (при в1) |
| Semver-синхронизация | вечная, 8 крейтов | **нет** | нет |
| Вендорный гейт | не решает | не решает, но изолируется фичей | то же |
| Независимый reuse persist-lock | да | **нет (жертва)** | частично (в1) |
| Работа по импортам | нет | однократно | дважды (в1) |

**Рекомендация:** форма **(б) с фичами** — физическое слияние всех 10 библиотечных крейтов в `tor-socks5` с первого коммита; фича-матрица (§3) — единственный гибридный элемент; публикация — только после открытия вендорного гейта (§4).

---

## 2. Карта модулей

Пересчитанные объёмы (методика — Приложение A):

- всего packages/ + apps/: **144 файла / 52 178 строк**;
- vendor-clean 7 крейтов: **67 файлов / 20 198 строк** — persist-lock 8/1839, bridge-verify-core 4/1504, auth 9/2016, bridge-probe 28/8332, bridge-store 12/3527, proxy-config 4/2073, socks5-proto 2/907;
- vendor-blocked библиотеки (тянут arti-wrapper → пропатченные tor-крейты): **22 файла / 8 000 строк** — arti-wrapper 2/1360, bridge-fetcher 12/3043, dns-server 8/3597;
- не сливаются: android-ffi **12/7345** (cdylib), apps/socks5-proxy **42/16597** (CLI → §6), apps/pt-helper **1/38**.

Ключевой **внешний** потребитель единого крейта — `packages/android-ffi`: lib name `torsocks5`, `crate-type = ["cdylib"]` ONLY, на crates.io не идёт НИКОГДА (research §6). По `packages/android-ffi/Cargo.toml` он зависит от **8 из 10** библиотечных крейтов — всё, кроме `persist-lock` и `dns-server` (проверено по списку зависимостей). Всё, что он импортирует, обязано остаться `pub` в едином крейте.

### Что именно импортирует android-ffi (проверено grep'ом по packages/android-ffi/src)

| Внутренний крейт | Импортируемые имена | Где |
|---|---|---|
| arti_wrapper | `Settings`, `TorTunnel`, `BootstrapEvent`, `BootstrapEventCallback` | callback.rs:7; engine.rs:20,245,364; engine_bootstrap.rs:14 |
| auth | `AuthState`, `User`, `UsersConfig` | lib.rs:163; engine.rs:21; engine_tests.rs:17 |
| proxy_config | `Config`, `Loaded`, `BridgesConfig` | lib.rs:169; engine.rs:24; android_log.rs:39 |
| socks5_proto | сам крейт (`self`), `Reply`, `ConnectRequest`, `handshake`, `reply`, `PasswordVerifier` | engine.rs:25,39; engine_bridges.rs:667–713 |
| bridge_probe | `ResolverPolicy`, `ProbeRound`, `probe_round_with_policy`, `flush_dns_cache`, `save_persisted_dns_cache`, `load_persisted_dns_cache_async` | engine.rs:175,378–518; engine_bootstrap.rs:314–663; engine_bridges.rs:152–467; jni_bridges.rs |
| bridge_store | `BridgeStore` | lib.rs:164; engine.rs:23 |
| bridge_fetcher | `fetch_all`, `fetch_all_direct`, `FetchOutcome`, `Source`, `dedup_bridges` | engine_bootstrap.rs:678–717; engine_bridges.rs:337–454 |
| bridge_verify_core | `pt_reap::{pt_state_location_token, owned_process_targets, environ_state_location}`, `snapshot::snapshot_cache_dir` | jni_verify.rs:159–172; pt_reap.rs:399–428 |
| persist_lock | — (нет в зависимостях android-ffi) | |
| dns_server | — (нет в зависимостях android-ffi) | |

### Таблица модулей

| Текущий крейт (публичное имя / lib name) | Модуль в tor-socks5 | Статус | Почему |
|---|---|---|---|
| socks5-proto (`tor-socks5-proto` / `socks5_proto`) | `proto` | **pub** | android-ffi импортирует `handshake`, `reply`, `Reply`, `ConnectRequest`, `PasswordVerifier`. RFC 1928/1929 — публичное лицо крейта (минимальный SOCKS5-сервер, годный вне проекта). |
| auth (`tor-socks5-auth` / `auth`) | `auth` | **pub** | android-ffi: `AuthState`, `User`, `UsersConfig` (таблица выше). Argon2id+HMAC-кэш RFC 1929 — осмысленный наружный API. |
| proxy-config (`tor-socks5-config` / `proxy_config`) | `config` | **pub** | android-ffi: `Config`, `Loaded`, `BridgesConfig`. Ktav-схема настроек — то, что читает внешний embedder. |
| bridge-probe | `probe` | **pub** | android-ffi: `probe_round_with_policy`, `ResolverPolicy`, `ProbeRound`, `flush_dns_cache`, `save_persisted_dns_cache`, `load_persisted_dns_cache_async`. Курируемый re-export surface (research §4). |
| bridge-store | `store` | **pub** | android-ffi: `BridgeStore`. Здоровье мостов между рестартами — наружный контракт. |
| bridge-verify-core | `verify` | **pub** | **Противоречие с research §4** («внутренний DRY-экстракт») разрешается в пользу pub: android-ffi — один из двух исходных потребителей экстракта (crate-doc bridge-verify-core/src/lib.rs:1–4: извлечён из CLI-демона и Android JNI engine) — активно использует `pt_reap` и `snapshot` (таблица выше). Внутренний по происхождению — внешний по факту зависимости; pub обязателен. |
| arti-wrapper | `tor` | **pub** | android-ffi: `Settings`, `TorTunnel`, `BootstrapEvent`, `BootstrapEventCallback`. Самый востребованный наружу API (research §4: «the crate an external consumer would actually want»). |
| bridge-fetcher | `fetch` | **pub** | android-ffi: `fetch_all`, `fetch_all_direct`, `FetchOutcome`, `Source`, `dedup_bridges`. |
| dns-server (целевое имя **`tor-socks5-dns`**; текущее `dns-server`) | `dns` | **pub** | android-ffi его НЕ импортирует (нет в зависимостях). Нужен CLI (dns_wiring.rs:14–15) и внешним embedder'ам: запуск локального DNS-резолвера через Tor — заявленная функция (dns-server/src/lib.rs:1–9). Pub дёшев и честен. |
| persist-lock | `persist` | **pub(crate)** | Домен-агностичен, но в едином крейте нужен только внутренним модулям: auth (state.rs:46, users_config.rs:87), probe (dns.rs:689), store (persistence.rs:387), config (lib.rs:963), dns (cache.rs:227), CLI (candidate_pool.rs:66,295; users_cli.rs:130 и др.). android-ffi от него не зависит. Ни один pub-тип других модулей не вскрывает его типов: единственная сигнатура с `TempFileGuard` — `pub(super) save_persisted_dns_cache_with_writer` (bridge-probe/src/dns.rs:668–670). **Жертва варианта (б)**: независимое переиспользование пропадает (§1). Цена: 2 интеграционных теста (230 строк) и пример (81 строка) не видят `pub(crate)` → переносятся в `#[cfg(test)]`-юниты модуля. |

### Маппинг имён и коллизии

- lib name → модуль: `auth`→`auth`; `proxy_config`→`config`; `socks5_proto`→`proto`; `persist_lock`→`persist`; `bridge_probe`→`probe`; `bridge_store`→`store`; `bridge_verify_core`→`verify`; `arti_wrapper`→`tor`; `bridge_fetcher`→`fetch`; `dns_server`→`dns`. Десять различных имён модулей, ни одного дубля.
- Проверено по lib.rs: множества top-level `pub use`/`pub`-имён десяти крейтов **попарно не пересекаются**. Якорные примеры уникальности: `PathLock`/`TempFileGuard` (persist); `pt_reap`/`snapshot` (verify); `AuthState`/`UsersConfig`/`compute_hash`/`verify_hash` (auth); `BridgeIdentity`/`ProbeRound`/`ResolverPolicy`/`Report` (probe); `BridgeStore`/`HealthSnapshot`/`TransportStats` (store); `Config`/`Loaded`/`ParsedBridges`/`WatchdogConfig` (config); `TorError`/`TorTunnel`/`Settings`/`BootstrapEvent`/`BridgeCheckSettings` (tor); `FetchError`/`Source`/`FetchOutcome`/`UrlTarget` (fetch); `DnsServerError`/`DohProvider`/`OverrideResolver`/`ResolvedAnswer` (dns); `Reply`/`ConnectRequest`/`PasswordVerifier` (proto). Двух разных `pub use` с одинаковыми именами на одном уровне не остаётся.
- Коллизии имён **подмодулей** растворяются вложением: `mod dns` внутри bridge-probe (его DoH-обвязка) становится `probe::dns` и не конфликтует с top-level `dns`; `mod error` есть и у fetch, и у dns → `fetch::error`, `dns::error`. На одном уровне дерева двух одноимённых модулей не возникает.
- Единый extern-импорт потребителя: `use tor_socks5::config::Config;`, `use tor_socks5::auth::AuthState;` и т.д. (lib-таргет крейта `tor-socks5` даёт extern-имя `tor_socks5`).

**Рекомендация:** карта модулей — как в таблице; `persist` — `pub(crate)` (осознанная жертва (б)); пересмотр видимости/имени persist — только через развилку §8.3.

---

## 3. Матрица фич

Составлено по манифестам (все зависимости сверены с `packages/*/Cargo.toml`).

**Всегда-включённое ядро** (без фич): зависимости `anyhow`, `tokio`, `tracing`, `thiserror` — общий рантайм/ошибочный каркас. Точные подсчёты по секциям `[dependencies]` манифестов: `anyhow` — 8 из 10 модулей, `tracing` — 6, `tokio` — 5, `thiserror` — 4. `tokio` в ядре оправдан тем, что фича `socks5` входит в default и тянет его, а осмысленные комбинации без `bridges`/`socks5` не оставляют от крейта ничего. Плюс в ядре — модуль `persist` (его единственная внешняя зависимость — `anyhow`, packages/persist-lock/Cargo.toml:24).

### Зависимости крейтов → фичи (проверено по манифестам)

| Крейт | Внешние зависимости (кроме внутренних path и ядра) | Фича |
|---|---|---|
| socks5-proto | — (только `anyhow`+`tokio`) | `socks5` |
| persist-lock | — (только `anyhow`) | ядро |
| bridge-verify-core | `rusqlite` (features `backup`), `tracing` | `bridges` |
| auth | `argon2`, `sha2`, `hmac`, `subtle`, `dashmap`, `getrandom`, `ktav`, `serde` | `auth` |
| bridge-probe | `bridge-line`, `tokio`, `tokio-util`, `futures`, `hickory-resolver`, `url`, `rustls`, `tokio-rustls`, `webpki-roots`, `httparse` | `bridges` |
| bridge-store | `bridge-line`, `time` | `bridges` |
| proxy-config | `ktav`, `serde`, `indexmap`, `bridge-line` | `config` |
| arti-wrapper | `arti-client`, `tor-rtcompat`, `tor-chanmgr`, `tor-guardmgr`, `tor-linkspec`, `bridge-line` | `tor` |
| bridge-fetcher | `bridge-line`, `tokio`, `tokio-util`, `tokio-rustls`, `futures`, `rustls`, `webpki-roots`, `httparse`, `url` | `fetch` (⊆ tor∪bridges) |
| dns-server (tor-socks5-dns) | `hickory-proto`, `hickory-resolver`, `futures`, `httparse`, `rustls`, `serde`, `time`, `tokio-rustls`, `tokio-util`, `webpki-roots` | `dns` |

### Итоговая таблица фич

| Фича | Модули | Требует | Optional-зависимости crates.io, которые включает |
|---|---|---|---|
| `socks5` | `proto` | — | нет сверх ядра: proto зависит только от `anyhow`+`tokio` (socks5-proto/Cargo.toml) |
| `auth` | `auth` | — | `argon2`, `sha2`, `hmac`, `subtle`, `dashmap`, `getrandom`, `ktav`, `serde` |
| `bridges` | `probe` + `store` + `verify` | — | `bridge-line`, `hickory-resolver`, `rustls`, `tokio-rustls`, `webpki-roots`, `httparse`, `url`, `time`, `tokio-util`, `futures`, `rusqlite` |
| `config` | `config` | `bridges` | `ktav` (общая с auth), `indexmap`, `serde`; `bridge-line` — общая с bridges |
| `tor` | `tor` | — | `arti-client`, `tor-rtcompat`, `tor-chanmgr`, `tor-guardmgr`, `tor-linkspec`; `bridge-line` — общая |
| `fetch` | `fetch` | `tor`, `bridges` | новых нет — все зависимости fetch ⊆ tor ∪ bridges |
| `dns` | `dns` | `tor` | `hickory-proto` (только dns); `hickory-resolver`, `rustls`, `tokio-rustls`, `webpki-roots`, `httparse` — общие с bridges |
| `full` | всё | `socks5`, `auth`, `config`, `bridges`, `tor`, `fetch`, `dns` | — |

### Ответы на вопросы требовательности (по коду, не по интуиции)

- **dns ТРЕБУЕТ tor:** весь DoH-трафик dns-server ходит через `arti_wrapper::TorTunnel` (`use arti_wrapper::TorTunnel` в packages/dns-server/src/doh_client.rs:19 и server.rs:58; crate-doc lib.rs:1–4: «every DoH request tunnelled through the live Tor connection»). Модуль `overrides` умеет ходить в обход туннеля, но это надстройка над ядром, требующим TorTunnel.
- **fetch ТРЕБУЕТ tor и bridges:** `use arti_wrapper::TorTunnel` (fetch.rs:5, http.rs:9) и `use bridge_probe::…` (dedup.rs:6, direct.rs:17, fetch.rs:7, http.rs:10, parse.rs:5).
- **bridges НЕ требует tor** — probe/store/verify не импортируют ни одного arti/tor-крейта (проверено по манифестам: ни одна из трёх зависимостей не встречается). Это **tor-free поддерево** и самостоятельная ценность единого крейта: пробинг/хранение/верификация мостов без встраивания Tor; отдельно подчеркнуть в README.
- **tor НЕ требует bridges:** arti-wrapper использует `bridge-line`, но не `bridge-probe` (packages/arti-wrapper/Cargo.toml: ровно 11 зависимостей — arti-client, tor-rtcompat, tor-chanmgr, tor-guardmgr, tor-linkspec, tokio, futures, anyhow, thiserror, tracing, bridge-line). Общая optional-зависимость `bridge-line` включается и фичей `tor`, и фичей `bridges` независимо — Cargo это допускает.

### default и ядро

- **default:** `default = ["socks5", "auth", "config", "bridges"]` — tor-free подмножество (config тянет bridges транзитивно, так что декларация полна и самосогласованна).
- Почему tor не в дефолте ДО открытия гейта: default с tor означал бы, что каждый `cargo add tor-socks5` молча собирает стоковый arti без фиксов vendor (§4) — недопустимо.
- После открытия гейта default расширяется до `full` на минорном бампе — 0.x semver это позволяет (§7).
- **persist:** **всегда-включённое ядро** — нужен 5 из 10 модулей (`auth`, `probe`, `store`, `config`, `dns`) плюс CLI; единственная зависимость `anyhow`; фичевый gating не окупает усложнение матрицы.
- **proto:** **под фичей `socks5`** (default-on): чтобы существовало имя «без SOCKS5-протокола» для экзотических комбинаций; цена — один `#[cfg(feature = "socks5")]`.

**Рекомендация:** таблицы выше; `default = ["socks5","auth","config","bridges"]`; `persist` — ядро без фичи; `proto` — фича `socks5`; `full` — всё; расширение default до `full` — только после гейта и только минорным бампом.

---

## 4. Вендорный гейт (ключевой раздел)

**Фиксация:** с включённой фичей `tor` пакет ЧЕСТНО публиковать нельзя, пока `[patch.crates-io]` не сократится до единственного `tor-circmgr`.

Механика (research §1; подтверждено Cargo Book «Overriding Dependencies» + rust-lang/cargo#6535/#13222/#10440):

- `[patch]` **вырезается** при `cargo package`/`cargo publish` и **не распространяется** на потребителей; учитывается только `[patch]` корневого манифеста конечного потребителя.
- Потребитель, включивший `tor`, разрешит **стоковые** crates.io-версии `saturating-time`, `tor-dirclient`, `tor-dirmgr`, `tor-chanmgr`, `tor-guardmgr`, `arti-client` и **молча** потеряет все фиксы vendor/README.md:
  - Windows 100%-CPU вечный цикл в `saturating-time` (ради него форк и заводился);
  - вечный bootstrap fetch'а дескрипторов мостов;
  - отравленный навсегда netdir через panic-poisoning `RwLock`;
  - `SQLITE_BUSY`/`SQLITE_LOCKED`, классифицируемые как fatal;
  - зомби-каналы после смены сети;
  - дыры guard-readiness/recovery.
- Это не ошибка сборки, а **тихая деградация** — худший режим для Tor-клиента; research §1 прямо называет публикацию в таком состоянии «actively worse than not publishing at all».

Что должно приехать в апстрим, чтобы гейт открылся (статусы — research §2):

| Крейт | Фикс(ы) | Статус |
|---|---|---|
| `saturating-time` | lazy `unwrap_or_else` против не-терминирующего поиска на Windows | **Drafted**; нужен rebase на вышедший 0.4.x |
| `tor-dirclient` | idle-таймаут чтения + `Content-Length` bound | **Drafted** |
| `tor-dirmgr` 1/3 | таймаут fetch мостов + retry/parallelism 4→12 / 30s→5s | **Drafted** |
| `tor-dirmgr` 2/3, 3/3 | panic-poisoning `shared_ref.rs`; реклассификация `SQLITE_BUSY`/`SQLITE_LOCKED` | Plausible, не drafted |
| `tor-chanmgr` 2 фикса | `terminate_all_channels()` (живой апстрим-work-item gitlab.torproject.org/tpo/core/arti/-/work_items/1600) + PT connect timeout 10s→45s | Plausible, не drafted |
| `tor-guardmgr` + `arti-client` | пара: `usable_guard_events`/`reset_disabled_guards` ↔ `ready_for_traffic` | Mixed (правдоподобно, но спорный объём) |
| `tor-circmgr` | bandwidth-percentile форк — **не апстримится НИКОГДА**, но остаётся допустимым: при дефолтах (`min_bandwidth_percentile=0`) поведение идентично стоку (Cargo.toml:110–117) | постоянный житель `[patch]` |

Варианты ДО открытия гейта:

- **(i) фича `tor` объявлена, default-off, «громкое предупреждение» в доках — НЕ защищает.**
  - Published-манифест содержит optional-зависимости; любой `cargo add tor-socks5 --features tor` **молча** собирает стоковый arti.
  - Предупреждение не блокирует ничего: мы даже не можем детектировать эту сборку со своей стороны.
- **(ii) не публиковать вовсе до открытия гейта.**
  - Крейт живёт в репозитории и обслуживает path-потребителей (android-ffi, CLI); crates.io молчит до гейта; первая публикация — 0.1.0 уже с полной фича-матрицей.
- **(iii) публиковать pre-gate версии, в которых фичи `tor`/`dns`/`fetch` и CLI-бин физически отсутствуют**, добавляются аддитивно в 0.2.0 после гейта.
  - Плюс: проблемная поверхность опубликованного артефакта равна нулю — честно.
  - Минусы: `cargo install tor-socks5` до гейта даёт **не-работающий прокси** (библиотека без tor — внедрять нечего, бина нет); semver-стабильной приходится держать две разные поверхности (0.1.0 без tor → 0.2.0 с tor); главный выигрыш слияния — форма репозитория — достигается и без публикации; ценность pre-gate публикации низкая.

**Рекомендация: (ii) — не публиковать ничего до открытия гейта.** Ценность pre-gate публикации (iii) не окупает двойную semver-поверхность и пустой `cargo install`; вариант (i) недопустим по определению.

**Критерий открытия гейта (все три пункта одновременно):**

1. `[patch.crates-io] == { tor-circmgr }` — все остальные записи ушли, потому что фиксы доброшены в апстрим;
2. `cargo publish --dry-run` на едином крейте проходит (в проверочной сборке — с включённой фичей `tor`);
3. все перечисленные фиксы находятся в **выпущенной** апстрим-версии (не «PR отправлен», а «релиз с фиксом вышел»), на которую можно перевести `[workspace.dependencies]`.

---

## 5. Бинарь

- При цельной форме CLI отдаётся тем же крейтом через `[[bin]]` — потребитель получает `cargo install tor-socks5` бесплатно; это ровно цель «цельного пакета».
- **Ключевой факт (поведение Cargo, документировано): cargo НЕ собирает `[[bin]]`-таргеты зависимостей.** Когда `tor-socks5` используется как библиотека, собирается только lib; bin/examples/tests/benches зависимостей не строятся.
- Проверено по `apps/socks5-proxy/Cargo.toml` — зависимости, нужные только бину:

| Зависимость бина | Условие | Комментарий |
|---|---|---|
| `clap` | всегда | CLI-парсинг |
| `service-manager` | всегда | установка как OS-сервиса |
| `rpassword` | всегда | ввод пароля в CLI |
| `serde_json` | всегда | только CLI (в packages/ не встречается — проверено) |
| `lyrebird` | всегда | бину нужен для запуска PT |
| `tor-error`, `tracing-subscriber`, `tracing-appender`, `tempfile` | всегда | CLI-обвязка |
| `windows-service`, `windows-sys` | `cfg(windows)` | сервис/JobObjects под Windows |
| `daemonize` | `cfg(all(unix, not(target_os = "android")))` | `--daemon` под Unix |

- **`rusqlite` — отдельный случай:** он нужен самой библиотеке (модуль `verify` = bridge-verify-core, packages/bridge-verify-core/Cargo.toml), поэтому в вес бинаря не записывается и в фичу `cli` не попадает; он живёт в фиче `bridges`.
- Смешанные зависимости: `indexmap` нужен библиотеке (config), `time` — store/dns, `getrandom` — auth (заявлен и в auth, и в CLI) — они остаются в фичах соответствующих модулей, не в `cli`.
- Оценка честно:
  - **плюс** — `cargo install` из одного имени, ровно цель цельного пакета;
  - **минусы** — манифест тяжелеет (список optional-deps фичи `cli`), и бину нужен `required-features`, иначе «холодные» сборки без фич падают на отсутствующей поверхности.

**Рекомендация:** включать `[[bin]]` (после открытия гейта), `required-features = ["tor", "cli"]`; фича `cli = ["dep:clap", "dep:service-manager", "dep:rpassword", "dep:serde_json", "dep:lyrebird", "dep:tor-error", "dep:tracing-subscriber", "dep:tracing-appender", "dep:tempfile", …]` + target-specific `windows-service`/`windows-sys`/`daemonize`. Имя бина (`tor-socks5` vs `socks5-proxy`) — развилка §8.2.

---

## 6. Стратегия перехода

### Единовременное слияние, не поэтапность

- Поэтапный план («этап 1: слить vendor-clean 7; этап 2: добавить tor/fetch/dns») **ничего не выигрывает**: публикация всё равно заблокирована вендорным гейтом (§4), промежуточной публикуемой точки не существует.
- Зато поэтапность **удваивает работу по импортам** (65 строк `use` + ~270 строк квалифицированных путей переписывались бы дважды) и дважды трогает CI.
- Фича `tor` просто выключена в дефолте: модули `tor`/`fetch`/`dns` компилируются в CI с первого коммита слияния (обязательный прогон `--all-features`), физического «второго этапа» нет.

### Судьба членов воркспейса

- **`apps/socks5-proxy`** (42 файла / 16 597 строк; без бенча src = 41 файл / 16 543 строки) → `src/cli/` внутри крейта + `src/bin/socks5-proxy.rs` (или корневой main) как точка входа; модули CLI объявляются **только** из бина (не из lib.rs), чтобы lib-сборка не компилировала CLI-код и не требовала `cli`-зависимостей. Бенч `socks5_bench` (54 строки) → `benches/`.
- **`apps/pt-helper`** (1 файл / 38 строк; только `lyrebird`, `tokio`, `anyhow` — vendor-блокировке не подвержен) → остаётся отдельным членом воркспейса; Android-специфичен, на crates.io не нужен.
- **`packages/android-ffi`** → остаётся cdylib-членом воркспейса, зависящим **по path от корневого `tor-socks5` с фичей `tor`**; на crates.io не идёт НИКОГДА (research §6). Его 11 `use`-строк внутренних крейтов переписываются на `tor_socks5::…`.
- **`vendor/*`** → остаются под апстримовыми именами в `[patch.crates-io]` (7 записей, Cargo.toml:86–117); в публикуемый крейт не входят никогда.
- **Примеры:** 7 крейтов имеют рабочие примеры в `packages/*/examples/`:

| Пример | Крейт | Строк |
|---|---|---|
| `atomic_save.rs` | persist-lock | 81 |
| `pt_reap_decisions.rs` | bridge-verify-core | 103 |
| `auth_flow.rs` | auth | 102 |
| `dns_lookup.rs` | bridge-probe | 119 |
| `health_snapshot.rs` | bridge-store | 87 |
| `config_walkthrough.rs` | proxy-config | 96 |
| `minimal_server.rs` | socks5-proto | 66 |

  Итого **7 файлов / 654 строки**. **Коллизий имён пример-бинарей нет** (все имена различны, таблица выше) → переезжают в `examples/` крейта как есть; 7 `use`-строк (по одной на пример) переписать на `tor_socks5::…`.
- **README:** 8 пакетных README (7 vendor-clean + dns-server) схлопываются в один крейтовый README с разделами по модулям; корневой README.md (сейчас про CLI-прокси: «A local SOCKS5 proxy that tunnels TCP through Tor…») становится лицом крейта.
- **Бенчи:** `auth_bench` (75 строк), `probe_bench` (93), `fetcher_bench` (37), `socks5_bench` (54) → `benches/`; имён не конфликтуют; 18 квалифицированных вхождений внутренних имён в бенчах переписать.

### Объём работ (пересчитано 2026-09-20)

| Что | Сколько |
|---|---|
| Манифесты | **13 → 1** публикуемый (`tor-socks5`) + **2** непубликуемых члена (android-ffi, pt-helper); корневой Cargo.toml становится `[workspace]` + `[package]` |
| Файлы/строки модулей «как есть» в `src/` | 10 библиотечных крейтов: 89 файлов / 28 198 строк минус примеры 7/654, бенчи 3/205, интеграционные тесты 5/310 → **74 файла / 27 029 строк**; плюс CLI **41 файл / 16 543 строки**; итого **115 файлов / 43 572 строки** |
| lib.rs → mod-объявления | 11 lib.rs суммарно **3 528 строк**. 7 многомодульных сжимаются до `mod`-дерева + док-комментов: persist-lock 47, bridge-verify-core 16, auth 121, bridge-probe 54, bridge-store 247, dns-server 32, bridge-fetcher 31. 3 однофайловых переезжают целиком как модули: proxy-config 971 → `config.rs`, socks5-proto 841 → `proto.rs`, arti-wrapper 857 → `tor.rs` |
| `use <внутренний-крейт>::` | **65 строк** (63 `use` + 2 `pub use X::*` в apps/socks5-proxy/src/config.rs:4 и socks5.rs:4). Разбивка по месту: packages-внутренние **25** (на `crate::x::`), CLI **27+2** (на `crate::x::`), android-ffi **11** (на `tor_socks5::x::`). По именам: arti_wrapper 13, bridge_store 12, bridge_probe 11, persist_lock 10, auth 6, proxy_config 5(+1 glob), socks5_proto 2(+1 glob), dns_server 2, bridge_verify_core 1, bridge_fetcher 1 |
| Квалифицированные пути вне `use` | **~272 строки** (grep `X::` вне use-строк): bridge_probe 62, arti_wrapper 55, persist_lock 40, bridge_fetcher 35, auth 27, socks5_proto 21, bridge_verify_core 16, dns_server 8, proxy_config 5, bridge_store 3; включая ~18 вхождений в 4 бенчах. Переписываются на `crate::x::`/`tor_socks5::x::` или заменяются `use`-строками |
| README | **8** пакетных → **1** крейтовый + корневой |
| Примеры / бенчи / тесты | примеры **7/654** → `examples/`; бенчи **4/259** → `benches/`; интеграционные тесты **5/310** (persist-lock 2/230, bridge-probe 1/36, proxy-config 1/24, bridge-fetcher 1/20) → в `#[cfg(test)]`-модули (persist — из-за `pub(crate)`; остальные могут остаться интеграционными с `use tor_socks5::…`) |

### Риски (качественно)

- **Коллизии типов между крейтами.** Реальные Error-типы (по lib.rs/error.rs): `TorError` (packages/arti-wrapper/src/lib.rs:21), `FetchError` (packages/bridge-fetcher/src/error.rs:10), `DnsServerError` (packages/dns-server/src/error.rs:10) — имена различны, конфликтов нет. «Опасные» generic-имена (`Config`, `Source`, `Loaded`, `Settings`, `Outcome`, `Report`) на top-level не пересекаются (§2), но `use tor_socks5::*;` у потребителя станет минным полем — glob-реэкспортов на корневом уровне не делать.
- **Лимит файла 1000 строк** (scripts/check-line-limit.sh, MAX_LINES=1000, CI): будущие `config.rs` 971, `tor.rs` 857, `proto.rs` 841 — вплотную к пределу; любое развитие этих модулей = предварительное разбиение файлов, лучше сделать его ещё при переезде.
- **Фича-матрица** должна собираться во всех комбинациях: добавить в CI прогоны `--no-default-features`, `--features tor`, `--all-features`.
- **`dns`-модуль и SDK-03:** переименование `dns-server` → `tor-socks5-dns` меняет только строку в таблице §2; карта модулей от порядка задач не зависит.

**Рекомендация:** единовременное слияние всех 10 библиотечных крейтов с первого коммита; CLI — внутрь крейта (`src/cli` + bin); android-ffi и pt-helper остаются членами воркспейса; публикация отложена гейтом (§4).

Порядок исполнения (верхнеуровневый чек-лист, каждая строка — отдельная задача):

1. создать скелет крейта `tor-socks5` (корневой `[package]` + фича-матрица §3), перенести 10 модулей по карте §2, переписать 65 `use`-строк и ~272 строки квалифицированных путей;
2. перенести CLI в `src/cli` + bin с `required-features`, бенчи в `benches/`, примеры в `examples/`, интеграционные тесты внутрь модулей;
3. перевести android-ffi на path-зависимость от корневого `tor-socks5` (фича `tor`) и переписать его 11 `use`-строк;
4. схлопнуть 8 пакетных README в крейтовый, корневой README сделать лицом крейта;
5. следить за лимитом файлов 1000 строк (scripts/check-line-limit.sh): если переезд порождает файлы-нарушители (кандидаты — config/tor/proto, §6 «Риски»), разбивать их в самом переезде, не откладывая;
6. публикация — только по критерию гейта (§4).

---

## 7. Semver / MSRV политика

- Первая публикация — **0.1.0**; 0.x semver допускает ломающие изменения на минорном бампе — штатный режим до 1.0.
- `rust-version = "1.89"` зафиксировано в `[workspace.package]` (Cargo.toml:23) и наследуется всеми членами; поднимать только отдельным решением.
- **Фичи — только аддитивно:** новая фича или новый optional-dep не ломает потребителей.
- **Изменение default-фич в 0.x** (и сужение, и расширение) — допустимый, но **ломающий минор**: потребитель без `default-features = false` получает другой граф зависимостей.
- Каждый ломающий минор документируется в `CHANGELOG.md` (файл существует в корне репозитория).

**Рекомендация:** правила выше без исключений; расширение default до `full` после открытия гейта оформить минорным бампом + записью в CHANGELOG.md.

---

## 8. Развилки для решения пользователя (финальный список)

| # | Вопрос | Варианты | Рекомендация документа |
|---|---|---|---|
| 1 | Публиковать ли pre-gate вообще? | (ii) не публиковать до гейта / (iii) tor-less 0.1.0 (без фич tor/dns/fetch и без бина) | **(ii)** |
| 2 | `[[bin]]` в едином крейте? | да, `required-features=["tor","cli"]` / нет (CLI остаётся отдельным непубликуемым членом, как сейчас); имя бина: `tor-socks5` (совпадает с пакетом) или `socks5-proxy` (как сейчас) | **да, после гейта**; имя — на выбор пользователя |
| 3 | Имя и видимость модуля persist-lock | `persist` / `persist_lock` / `lock`; видимость `pub(crate)` / `pub` | **`persist`, `pub(crate)`** |
| 4 | default-фичи pre-gate (актуально только при выборе (iii) в п.1) | `["socks5","auth","config","bridges"]` / `["socks5"]` / пустой default | **`["socks5","auth","config","bridges"]`** |
| 5 | Судьба имён `tor-socks5-auth` / `tor-socks5-config` / `tor-socks5-proto` | не публиковать и не резервировать / попытаться резервировать | **не публиковать**: цельный пакет эти имена не использует, а резервирование без публикации crates.io не поддерживает |
| 6 | Очерёдность апстрим-патчей (вне рамок задачи, но определяет дату открытия гейта) | по возрастанию готовности: Drafted (saturating-time rebase, tor-dirclient, tor-dirmgr 1/3) → chanmgr-пара (work item 1600) → guardmgr+arti-client / другой порядок | **по возрастанию готовности** |

К п.5 — уточнение, почему «не резервировать»: crates.io не позволяет занять имя без публикации (публикация = занятие), а «пустышка»-релиз ради занятия имени прямо противоречит решению «ничего не публиковать сейчас». Имена остаются свободными для будущих решений.

**Рекомендация по секции:** решить п.1–5 до старта работ по слиянию (все пять влияют на целевой манифест); п.6 вести параллельно — он определяет только календарную дату публикации, а не форму крейта.

---

## Приложение A. Методика пересчёта чисел

Однострочники, которыми получены все цифры этого документа (worktree sdk-01, 2026-09-20):

- файлы/строки крейта: `git ls-files '<crate>' | grep '\.rs$' | wc -l` и `… | xargs wc -l | tail -1`;
- итог: `git ls-files 'packages/**/*.rs' 'apps/**/*.rs' | wc -l` → 144; те же файлы через `wc -l` → 52 178;
- `use`-импорты: по каждому внутреннему имени (`auth`, `proxy_config`, `socks5_proto`, `persist_lock`, `bridge_probe`, `bridge_store`, `bridge_verify_core`, `arti_wrapper`, `bridge_fetcher`, `dns_server`) — `grep -hE "\buse <name>(::|;| as )"` → 65 (из них 63 с якорем `^\s*use`; 2 — `pub use X::*` в CLI);
- квалифицированные пути вне `use`: те же имена, `grep -E "<name>::"` минус строки `^(pub )?use` → суммарно ~272 строки;
- размеры lib.rs: `wc -l packages/*/src/lib.rs` (таблица в §6);
- примеры/бенчи/тесты: `git ls-files | grep -E 'examples/|benches/|/tests/'`;
- android-ffi: список зависимостей — `[dependencies]` в packages/android-ffi/Cargo.toml (8 внутренних path-зависимостей с `version = "0.1.0"`); его внутренние импорты — `grep -rnoE '<name>::' packages/android-ffi/src`.

Контрольные цифры задачи (144/52 178; 67/20 198; 22/8 000; 12/7 345; 42/16 597; 1/38; 65 use-строк) **совпали с пересчитанными** — расхождений нет.

---

*Все факты о коде взяты из файлов этого worktree на 2026-09-20; все числа пересчитаны самостоятельно (Приложение A); факты о crates.io проверены 2026-09-20. Единственное утверждение, взятое из документации инструмента, а не из файлов репозитория, — поведение Cargo «bin-таргеты зависимостей не собираются» (§5); оно документировано в Cargo Book.*
