# Тестирование — сегментированный CI

## Текущий контракт (#62, выполнение не проверено)

CI использует `scripts/testing/ci_planner.py` для выбора затронутых сегментов и пакетов. Для PR используется merge-base, для push — предыдущий SHA; ручной запуск affected требует `base_ref`. Только ручной `sprint-full` выбирает полный план. Отсутствие базы, metadata или соответствия вызывает ошибку, а не переход к полному запуску. Плановый workflow запускает ограниченные stress-, vendor- и feature-проверки, а не полную матрицу workspace. Лицензионный lifecycle выполняется только для PR.

При переносе на ветку с лицензионным workflow задайте его job `required` имя `License required` и настройте защиту ветки на оба различных check: `CI required` и `License required`. В текущей ветке лицензионного workflow нет.

Хук pre-push сохраняет проверки форматирования и структуры и запускает clippy, тесты и doctest для тех же запланированных Rust-пакетов. `FULL=1` — явное локальное переопределение; ветки, теги и ошибки не приводят к полному запуску. Для новой ссылки хук использует merge-base с `origin/main` и сообщает об ошибке, если он недоступен. Обёртка требует `--base <ref>`, если явно не указан `--full`. Выбор сравнивает коммиты, а не незакоммиченные изменения; команды выполняются на рабочем дереве. Push коммита, отличного от HEAD, нескольких коммитов или с несовместимыми базами отклоняется. Push только с удалением ссылок пропускает проверки. Регрессионная самопроверка выполняется в CI, а не в хуке.

```bash
git config core.hooksPath .githooks
scripts/testing/test-affected.sh --base origin/main --mode list
scripts/testing/test-affected.sh --base origin/main --mode args
scripts/testing/test-affected.sh --base origin/main --mode run --kind all
TEST_AFFECTED_DRY=1 git push
FULL=1 git push
```

`git push --no-verify` обходит хук; используйте его только в экстренном случае. `cargo nextest` не выполняет doctest, поэтому они запускаются отдельно. `saturating-time` исключён из doctest, поскольку его примеры могут зависнуть в Windows.

Запускайте `--all-features` для vendored crate отдельным вызовом cargo, не вместе с пакетом приложения: объединение features иначе может привести к несовместимой комбинации upstream features.

## Нестабильные тесты

Профиль `ci` не повторяет упавшие тесты. Для расследования используйте `cargo nextest run --profile flaky-hunt --stress-count N` или `--stress-duration 1h`. Наборы с сокетами и остановленными часами используют группу `sockets-and-clocks` для ограничения параллелизма.

Историческая модель уровней и измерения сохранены в [`docs/plans/test-tiers.md`](../plans/test-tiers.md). Эти изменения и их выполнение в CI не проверены.
