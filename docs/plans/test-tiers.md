# План: уровни тестирования — по задаче только связанное, полный прогон реже

Статус: **дизайн** (задача TST-01). Реализация — TST-02 … TST-08. Данные получены
по `cargo metadata` и статическому подсчёту тестов (без тяжёлых прогонов).

## Проблема

- `.githooks/pre-push` на каждый пуш делает `fmt` + `clippy --workspace` + `cargo test --workspace`
  (~1300 тестов, минуты). На feature-ветке с правкой одного пакета это лишнее, а нестабильный
  тест блокирует пуш (так было с `tor-socks5-dns`, см. FLK-01).
- CI гоняет `cargo test --workspace` на трёх ОС для каждого PR и каждого пуша в `main`.
- Раннеры аккаунта общие: очередь уже срывала релиз, лишние джобы дороги.

## Факты (ПРОВЕРЕНО по репозиторию на `f07d29e`)

17 пакетов workspace, ≈1298 тестов (статический подсчёт `#[test]`/`#[tokio::test]`/`proptest!`).

| Пакет | Путь | Тестов | Сокеты/время* | Обратных зависимостей |
|---|---|---:|---:|---:|
| socks5-proxy | apps/socks5-proxy | 326 | 82 | 0 |
| tor-socks5-dns | packages/dns-server | 148 | 124 | 1 |
| bridge-probe | packages/bridge-probe | 135 | 26 | 5 |
| tor-socks5-config | packages/proxy-config | 110 | 0 | 2 |
| bridge-fetcher | packages/bridge-fetcher | 103 | 9 | 2 |
| bridge-store | packages/bridge-store | 74 | 0 | 2 |
| tor-circmgr | vendor/tor-circmgr | 73 | 40 | 6 |
| tor-guardmgr | vendor/tor-guardmgr | 62 | 27 | 7 |
| android-ffi | packages/android-ffi | 54 | 13 | 0 |
| arti-client | vendor/arti-client | 50 | 1 | 5 |
| tor-socks5-auth | packages/auth | 48 | 0 | 2 |
| bridge-verify-core | packages/bridge-verify-core | 39 | 0 | 2 |
| arti-wrapper | packages/arti-wrapper | 28 | 0 | 4 |
| persist-lock | packages/persist-lock | 25 | 0 | 8 |
| tor-socks5-proto | packages/socks5-proto | 14 | 7 | 2 |
| saturating-time | vendor/saturating-time | 9 | 0 | 0 |
| pt-helper | apps/pt-helper | 0 | 0 | 0 |

\* число вхождений `TcpListener/UdpSocket::bind|connect`, `start_paused`, `tokio::time::pause/advance`,
`MockRuntime` — признак реальных сокетов и/или паузы часов (источник флейков: порты Windows,
`resume()`, RST вместо FIN). Данные: `.target-local/tests/inventory.json` (локально).

- Граф зависимостей мелкий: приложения (`socks5-proxy`, `android-ffi`) — листья, у `persist-lock` самый
  широкий охват (8). Единственная dev-зависимость между members: `tor-circmgr -> tor-guardmgr`.
- CI (`.github/workflows/ci.yml`): `on: push: branches: [main]` и `pull_request`; отдельный
  `concurrency` с `cancel-in-progress`. **Пуш ветки без PR CI не запускает** — для проверки миграции
  (UPS-07) нужен draft PR или явная ветка в `on.push.branches`.
- Не-Rust файлы, влияющие на тесты (нужны правилам выбора):
  - `README.md`, `tor-socks5.example.ktav` читает `packages/proxy-config/tests/shipped_examples.rs`
    (+ `include_str!` примера мостов в `packages/proxy-config/examples/`);
  - `README.md`, `docs/architecture.md`, `docs/guide/*.md` вшиты в бинарь через `include_str!`
    в `apps/socks5-proxy/src/commands/help_cmd.rs` (ломают сборку `socks5-proxy` при переименовании).
- Не members: `vendor/tor-chanmgr`, `vendor/tor-dirmgr`, `vendor/tor-dirclient`; их тесты в
  `cargo test --workspace` не входят (только по явной проверке пакета). Это пробел покрытия, который
  нужно закрыть ночным контуром (T3).
- Doctests: `cargo nextest` их не запускает — нужен отдельный `cargo test --doc`.

## Уровни

| Уровень | Что запускается | Когда |
|---|---|---|
| **T0** | `fmt --all --check`; `clippy` затронутых пакетов; `check-line-limit`, `check-dir-entries`, `check-publish-guard` | всегда (дёшево) |
| **T1** | T0 + тесты и doctests **затронутых пакетов и их обратных зависимостей** (`scripts/test-affected.sh`) | pre-push по умолчанию; PR и ветки в CI |
| **T2** | полный `cargo nextest run --workspace` + doctests + clippy workspace, все ОС | push в `main`/`upstream-*`, теги, `FULL=1`, `workflow_dispatch` |
| **T3** | ночной: T2 + повторы нестабильных наборов (профиль `flaky-hunt`) + тесты невходящих в members vendor-крейтов + `cargo hack` по фичам выбранных крейтов + отчёт | `schedule` раз в сутки |

«Конец спринта» = T2 на `main`/теге плюс последний зелёный T3; в середине работы достаточно T0/T1.

## Правила выбора затронутых пакетов (T1)

1. База: `git merge-base HEAD <upstream|origin/main>`; список файлов `git diff --name-only <база>`.
2. Файл внутри пакета-члена → этот пакет. Затем замыкание по **обратным** зависимостям
   (обычные и dev), то есть правка `persist-lock` запускает тесты 8 зависящих пакетов.
3. Данные-файлы: `README.md`, `tor-socks5.example.ktav` → `tor-socks5-config`, `socks5-proxy`;
   `docs/architecture.md`, `docs/guide/**` → `socks5-proxy`; `packages/proxy-config/examples/**` → `tor-socks5-config`.
4. **Всегда FULL (T2):** `Cargo.toml` (корень), `Cargo.lock`, `.cargo/**`, `.config/**`,
   `rust-toolchain*`, `vendor/<не член>/**` (`tor-chanmgr`, `tor-dirmgr`, `tor-dirclient`), любые правки
   списка фич. Причина: единый граф зависимостей и унификация фич, как показала миграция на Arti 0.47
   (тесты `tor-circmgr` не собирались из-за фич, которых нет в нашем наборе).
5. `.github/**`, `.githooks/**`, `scripts/**`: тестов не запускать, но T0-проверки и самотесты
   скриптов; CI-файлы проверяются самим CI.
6. Только `docs/**` без перечисленных в п. 3: тесты не нужны (T0).
7. Пустой список → печатать «нечего тестировать», код 0.

## Нестабильность и конкурентность

- Профили `nextest` (TST-03): `default`, `ci` (без повторов, чтобы не маскировать флейки,
  JUnit), `flaky-hunt` (повторные прогоны). Группы с ограничением потоков для наборов с реальными
  сокетами и паузой часов (`tor-socks5-dns`, `tor-circmgr`, `tor-guardmgr`, `socks5-proxy`).
- Любой падающий тест чинится на месте; `retries` включать только в профиле расследования.
- Ночной контур публикует сводку в `GITHUB_STEP_SUMMARY` и при падении обновляет один issue.

## Не-цели

- Не менять сами тесты и не ослаблять проверки.
- Не заменять полный прогон на `main` и на тегах: безопасность релиза остаётся на T2.
- Не вводить кэширование результатов тестов между запусками (риск ложных зелёных).

## Критерии приёмки (для TST-02 … TST-08)

- Правка одного листового пакета запускает тесты только его (и обратных зависимостей) локально.
- Правка `Cargo.lock`/`vendor/**` — полный прогон; docs-only — пусто.
- Хук и CI печатают выбранный уровень и список пакетов.
- Ночью выполняется T3, падение оставляет единственный issue.
- Проверка на ≥15 последних коммитах `main`: выбор осмысленный (таблица в TST-08).

## Открытые вопросы

- Достаточно ли ночного T3, или нужен ещё T2 на `main` после каждого мержа (рекомендую: да, T2 на `main`).
- Нужен ли макОС в T1 (рекомендация: только ubuntu+windows на ветках, macOS — на `main`/ночью).
