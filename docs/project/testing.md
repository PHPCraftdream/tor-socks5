# Тестирование и выбор проверок

## Текущая политика

Обычный CI автоматически выбирает тесты по diff и графу зависимостей. Полный прогон выполняется в конце спринта только по отдельному явному триггеру. Неизвестное соответствие или недоказанная история дают ошибку, а не скрытый FULL.

История уровней и решений: [test-tiers.md](../plans/test-tiers.md). Действующий выбор определяют `scripts/testing/ci_planner.py` и workflow, а не прежние правила автоматического T2 для main, tags или `upstream-*`.

| Контур | Проверки | Условие |
|---|---|---|
| Служебные | Форматирование, line-limit, dir-entries, publish-guard, packageability и проверка плана | Обязательные проверки CI |
| Affected | Тесты, doctests, clippy затронутых пакетов и выбранные контрактные сегменты | Обычные PR, push и ручной `mode=affected` |
| Sprint-full | Все workspace-пакеты через явные `-p`-списки; Rust-матрица Ubuntu, macOS и Windows | Footer конца спринта либо ручной `mode=sprint-full` |
| Nightly | Ограниченные stress-, vendor- и feature-проверки | Отдельное расписание; не замена sprint-full и не полный workspace/3OS прогон |

MSRV 1.92, Android, native-portability, installer, release и лицензионные проверки выбираются соответствующими сегментами плана. Они не являются безусловной частью каждого лёгкого CI-запуска.

## Явный полный прогон

Полный CI выбирается только:

1. Точной отдельной строкой `CI-Full: sprint-end` в сообщении реального коммита проверяемого push/PR диапазона. Коммит может быть не последним.
2. Через **Actions → CI → Run workflow → mode=sprint-full**. Footer в коммите для ручного полного запуска не требуется.

Точный regex: `^CI-Full: sprint-end\r?$` для каждой строки сообщения после разбиения по `\n`. Допускается только завершающий `\r` от CRLF; регистр точный, один пробел после двоеточия, без начальных и конечных пробелов.

Не являются триггером: подстрока в prose, содержимое кода/diff/README, название ветки, PR description и сообщение синтетического PR merge-коммита.

```bash
git commit -m "тема" -m "CI-Full: sprint-end"
```

Ручной **mode=affected** остаётся доступен, требует `base_ref` и игнорирует footer: ручной выбор режима имеет приоритет. На каждую обычную фичу полный прогон не назначается.

Для PR `--head` — исходный `pull_request.head.sha`, а checkout — синтетический merge. Planner требует точные родители checkout: первый — base события, второй — исходный head. Произвольного родства недостаточно. Diff строится от merge-base исходных веток до фактического checkout; Cargo graph, blobs, документы и capabilities относятся к тому же checkout. Footer ищется отдельно только в исходных коммитах, без synthetic message.

Для push база — `event.before`, head — текущий коммит; база должна быть его предком. Merge-push сохраняет сообщения исходных коммитов диапазона. При squash эти коммиты не входят в main-историю: для полного прогона footer нужен в итоговом squash message, не в PR description. Для ручного affected `base_ref` — явно заданная валидная точка сравнения, не обязательно предок head.

Неизвестный ref, неправильные родители, несовпадение checkout/head или недоказанная push-история блокируют план. Они не превращаются в FULL или пустой зелёный результат.

## Выбор сегментов и пакетов

Planner сравнивает коммиты, а не staged/untracked изменения. Незакоммиченные Rust-исходники и манифесты, способные рассогласовать граф с выбранным деревом, отклоняются.

- Изменения внутри workspace-пакета выбирают его и обратное замыкание зависимостей. Учитываются normal, dev, build и target-specific связи, включая patched зависимости и aliases.
- README, обязательные examples и контрактная документация могут выбирать `docs-contract`; это не безусловный запуск всего Rust workspace. Обычные аналитические docs выбирают только необходимые лёгкие проверки.
- Workflows, CI helpers, hooks, installers, release и license tooling имеют собственные mappings. `.github/**` не означает «тестов нет».
- Manifest/lockfile, native flags, vendor и SDK изменения анализируются по соответствующим контрактам. Неизвестные критичные пути, в том числе неподдержанные `.config/**` или изменения toolchain, могут давать `missing mapping`, а не автоматический набор тестов.
- Установленные guarded capabilities нельзя тихо удалить или отключить. Проверяются фактические обязательные файлы и consumers.
- Ошибка Git, metadata, базы или mapping возвращает ненулевой код и диагностическое сообщение; готовый план не публикуется. Fallback на FULL отсутствует.

Пустой список Rust-пакетов сам по себе не означает отсутствие всех проверок: остаются служебные и другие выбранные сегменты. Режимы wrapper `list`/`args` печатают пустой вывод, если список соответствующих Rust-пакетов пуст; строки `nothing to test` контракт не обещает.

## Локальный wrapper и pre-push hook

Агенты не запускают локальные tests/build/check/clippy/metadata без отдельного разрешения; проверки этой работы выполняются в GitHub CI. Команды ниже описывают интерфейс для осознанного ручного использования разработчиком, не обязательные действия агента.

Подключение hook:

```bash
git config core.hooksPath .githooks
```

Hook читает pushed refs из stdin. Перед проверками он подтверждает, что pushed commit совпадает с текущим `HEAD`; несколько разных commits/bases в одном push отклоняются. Deletion-only push завершается без fmt/tests. Для нового ref база вычисляется как `merge-base HEAD origin/main`; для существующего — используется remote SHA. Недоступная база блокирует push.

Затем hook запускает fmt и структурные проверки, после них — wrapper. `FULL=1` явно передаёт wrapper `--full`; обычный вызов передаёт `--base`. Поскольку wrapper использует push-план, footer в диапазоне также может выбрать полный список пакетов. Это явный триггер, не fallback.

```bash
scripts/testing/test-affected.sh --base origin/main --mode list
scripts/testing/test-affected.sh --base origin/main --mode args
scripts/testing/test-affected.sh --base origin/main --mode run --kind all
scripts/testing/test-affected.sh --base origin/main --mode run --kind test
scripts/testing/test-affected.sh --full --mode run --kind all
TEST_AFFECTED_DRY=1 git push
FULL=1 git push
```

Без `--full` wrapper требует явный `--base`; автоматического поиска upstream/main внутри него нет. `--mode` принимает `list`, `args`, `run`; `--kind` — `test`, `clippy`, `all`. Проверки выполняются только для выданных планом `-p`-пакетов, на локальной ОС. Локальный полный список не создаёт трёхплатформенную CI-матрицу.

При наличии cargo-nextest используется nextest, иначе cargo test. Doctests запускаются отдельно для `library_packages`. `saturating-time` исключён: его поиск предела `SystemTime::max_value()` способен зависнуть на Windows; явный `cargo test --doc` не полагается только на manifest `doctest=false`.

`TEST_AFFECTED_DRY=1` печатает Rust-команды вместо их исполнения; это не подтверждение прохождения тестов. `git push --no-verify` обходит hook и не является исправлением причины отказа. Для автоматических агентов запрет локальных проверок сохраняется независимо от настройки hook.

### Features и vendor

`--all-features` для отдельного vendor-крейта не следует смешивать в одной Cargo-команде с app-пакетом. Например, `cargo clippy -p tor-circmgr -p socks5-proxy --all-features` может включить `vanguards`/`geoip` у tor-circmgr, но не соответствующие features arti-client. Это известная upstream non-additive комбинация (`TODO GEOIP`), а не основание ослаблять контракт или автоматически запускать весь workspace. Отдельные feature-проверки находятся в соответствующем CI-контуре.

## GitHub CI

`plan` исполняет `test_ci_planner.py` и `test_ci_integration.py`, затем `ci_planner.py`. Сводка содержит paths, reasons, full и full_trigger. Rust jobs получают `rust_rows` и явные `-p`-списки; JUnit artifact называется `junit-<target>`. MSRV, Android и прочие jobs запускаются только по выбранным сегментам.

`CI required` проверяет точный набор consumers: выбранные должны завершиться success, невыбранные — ожидаемым skipped. Failure, cancellation, неожиданный skip или отсутствующий consumer не дают зелёный итог.

В license-ветке есть отдельный `License required`; его нельзя путать с `CI required`. Реальный built-binary license lifecycle входит в `CI required` и выполняется только для PR. Явный footer-full PR не должен пропускать license-контракты, обязательные для того же affected PR. Ручной non-PR полный запуск не превращается в PR lifecycle.

Семицелевой producer остаётся отдельным trusted-main manual dispatch. Footer, PR или обычный полный CI не разрешают producer/promotion и не заменяют provenance, admission или юридическое approval. Branch protection должна учитывать оба разных check: `CI required` и `License required`.

Nightly ведёт один tracking issue `Nightly tests failed`. Успешный полный результат его собственного набора закрывает issue; skipped jobs считаются неполным запуском. Актуальные расписание и ограниченный набор определены `.github/workflows/nightly.yml`.

## Флейки и работа через rush/wrush

Падение теста исправляется на месте; retries в профиле `ci` остаются 0. Профиль flaky-hunt позволяет явно повторять выбранные проверки (`--stress-count N` или `--stress-duration`), но такой запуск не является доказательством исправления редкого сбоя без установленного механизма. Дополнительная нагрузка не назначается самовольно.

Реальные sockets и paused clocks проверяются с ограничением конкуренции группы `sockets-and-clocks` до четырёх потоков. Типичные направления расследования — Windows port reuse, clock pause/resume и RST вместо FIN; это гипотезы, не готовый диагноз.

Каждая rush/wrush-фаза изменяет свой scope и опирается на targeted CI затронутых сегментов. Полный прогон перед каждым merge не является стандартным шагом: он явно назначается в конце спринта footer или manual sprint-full. Запрет локального исполнения тестов агентами действует и внутри delegated worktrees.
