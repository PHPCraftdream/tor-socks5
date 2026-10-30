# Проверка source bytes candidate run 40934653900

## Статус и граница доверия

Два data-only запуска дали `PASS_DATA_ONLY`, exit 0, пустой список blockers. Это проверка сохранённых bytes и согласованности с заданными anchors, а не решение о составе binary, соответствующих исходниках, legal compliance или production authority. Родительский [отчёт](../release-components-40934653900.md) остаётся **PARTIAL**, включая 743 исходных blockers и открытые native/platform inputs, vendor attribution, MPL/LGPL/CDLA/CCADB и другие reviews. Новый SOCKS-код и будущий объединённый release эта проверка не авторизует.

Сохранённый ZIP artifact `12932028389` run `40934653900`: 853866809 байт, SHA-256 `75a58bb9393525b64f083105113771680bb561e1ff2f28f337fa584954b847d4`; размер и hash проверяются до и после разбора. Семь nested candidate совпадают по SHA-256 `c2787211e957ac6e1cac1d0b2fbf34e24cd0444b835febed8aef63e7e9dafa5e`. Project anchors предоставлены в задании и соответствуют аутентифицированным API-данным, указанным в родительском отчёте; SDK anchors также предоставлены в задании. На этом этапе новых API-запросов не было. Это допущения проверки, а не новое подтверждение их источника.

| Источник | Commit | Tree | Родители в порядке commit |
| --- | --- | --- | --- |
| project | `67f82c1e107ab24e8fd22afb9fd12134ffa7f982` | `8c5be9171f2a2fa0f83dc42a60d9bb731d891d4c` | `b4a27a0cb806ce4efeef23aa94b375ce2f4222d1`, `ff8a4253b1b632a50d45d91bbe23fa86d2a7f5bc` |
| SDK | `e754abaa88ce4f9745b4729652789ffc57f8ba4c` | `263db1bd209e4151eb4deadf532d423d0bf2b41c` | `98a8ac9004f4fc6eb5d6713037f213dded6404ba` |

Commit objects проверены по Git SHA-1, отдельно сверены tree и родители. Деревья восстановлены из Git blob SHA-1 **фактически прочитанных bytes** и modes фактических TAR headers, а не из встроенных OID; сравнивались с закреплёнными tree. Проверены точные множества путей project/SDK, размеры, SHA-256, blob OID и modes встроенных записей, а также `SOURCE-MODES.json` и default modes остальных source files. Вывод зависит от применимости Git SHA-1 и его устойчивости к подмене в данной модели; совпадение commit/parents/tree не создаёт production authority.

| Группа | Файлов | Сумма байт | TAR mode |
| --- | ---: | ---: | --- |
| project, включая vendor | 518 | 7950398 | все `0644` |
| SDK | 178 | 1738846 | все `0644` |

Независимая сводка размеров и modes: 696 файлов `0644`, исполняемых 0. Ещё 1939 source files имеют default `0644`; всего source paths 2635. `proof.json` содержит пофайловые размеры, SHA-256, Git blob OID и TAR modes.

## Digest и registry

Независимо реализован протокол из прочитанного как текст `bundle.py:165–166`, `admission.py:45–55,220–226`, `source_inventory.py:25–26,110–188`. Вложенные producer-файлы побайтно совпали с локальными текстами контракта; они не импортировались и не исполнялись:

| Файл | SHA-256 snapshot и локального текста |
| --- | --- |
| `bundle.py` | `f9aea866a01c5108a876bdf4d857dc6cadc20ef02725dc48aa177a1f9e525e74` |
| `admission.py` | `f2f10088a5abe6a4dfbd80d4c7f3bf1537c5e35aefdbbdebd30b8aa12f95479c` |
| `source_inventory.py` | `378890379a7f47a05146c1c1aa8b59aa1aa982ee412944e93030b138f9ed80f7` |

Общий source digest: `f8f9612d0bb2fb090da68a0722a401bf5b94312f86a7724922019c76a6c3fc44`, совпадает со всеми семью receipts. Сортированный список содержит 2635 дескрипторов source files `{path, sha256, size}`, дескриптор исходных bytes `GIT-SOURCES.json` и дескриптор канонического `SOURCE-MODES.json`, отфильтрованного по source paths: всего 2637. Канонизация: JSON с сортировкой ключей, `ensure_ascii=False`, разделителями `,` и `:`, UTF-8 и завершающим LF; SHA-256 считается от этих bytes.

Из проверенного project `Cargo.lock` (SHA-256 `44fec566e140a674ba45477f46ff616684d5e8ab5edcccc8d295a9e8ca975811`) получены registry identities и checksums: точное множество 727 `.crate` и SHA-256 каждого архива совпали. Архивы здесь не распаковывались: это не проверка expanded source или правовых условий. Внутренности остальных 714 `.crate`, сверх 13 ранее отдельно исследованных, по-прежнему не проверены.

Для каждого target build digest вычислен как SHA-256 канонического JSON-словаря относительный путь → SHA-256. Он охватывает шесть обязательных файлов `messages.jsonl`, `features.txt`, `toolchain.txt`, `native-evidence/linkage.txt`, `native-evidence/build-stderr.txt`, `expanded-sources.json` и все файлы `native-evidence/native/`. Это связывает сохранённые evidence bytes с receipt, но не доказывает полноту build inputs или соответствие binary исходникам.

| Target | Число evidence файлов | Пересчитанный `build_evidence_digest`, совпал с receipt |
| --- | ---: | --- |
| `aarch64-apple-darwin` | 115 | `447d139cf97c5317e5414003d630c076bab577d00e57eea4bdc66a4d8358f2e5` |
| `x86_64-apple-darwin` | 115 | `9d8b22c09090993f898ddd5f9b4133e80973dd54c8058c44dbef4013df855a1e` |
| `x86_64-pc-windows-msvc` | 124 | `6b298fdf8a35f45718bae4a2afd8e1bdc414f310fd7cd3abf4405af01212fe1e` |
| `aarch64-unknown-linux-musl` | 112 | `d8ebedeadce1b4847e3a0b406e39e9201c6824191603e45b13d917d26fa24a3e` |
| `aarch64-unknown-linux-gnu` | 112 | `e36c10caae8c10defe9bbf494119a9512618f98682763b9904d08fb22ae6ac6c` |
| `x86_64-unknown-linux-gnu` | 112 | `f322276ca62c2a711fb028bdda2be89b0b75089c4b7ee7ab0a26d7a5197fa703` |
| `x86_64-unknown-linux-musl` | 112 | `09fbda25cf92becce41c2e46b33a8a43b57daae0189aabd7fe992ecd29f9e830` |

## Воспроизведение и ограничения

Скрипт [prove-source-bytes.py](prove-source-bytes.py), 20098 байт, SHA-256 `967e9b1bc21c98934523ec00cf2403fe5b92b11035037a929224ed66bf481624`, явно импортирует только соседний доверенный аналитический `analyze-safe.py`, отключив запись bytecode. Код проекта, validators и данные архивов не исполняются и не импортируются. Нужны доверенный Python 3.12, административно доверенный каталог скриптов и неизменяемые на время анализа входы и цепочки путей: защиты от конкурентной локальной замены нет. Рабочий каталог не должен находиться внутри скачанных данных; пути передаются аргументами. Сетевые запросы и повторная проверка binary здесь не выполняются.

Из корня worktree, в Bash или Git Bash, с уже существующим `target`, для **нового свободного** имени:

```sh
python -I docs/project/license/release-components-40934653900-repro/prove-source-bytes.py --candidate target/stage1-data-20261029/candidate.zip --target-root target --output target/source-proof-fresh
```

Выход создаётся эксклюзивно; при занятом имени или ошибке выбрать другое, прежние evidence не перезаписывать и не удалять. Наблюдавшиеся запуски использовали те же аргументы, кроме уже занятых outputs `target/source-proof-20261030-a` и `target/source-proof-20261030-b`; оба exit 0, `PASS_DATA_ONLY`, blockers пусты. Их `proof.json` побайтно совпали: 732801 байт, SHA-256 `da0a383f93db18c9fd0a08947015685a575c49b834d78f00bd395ea6f8a7f259`. Отдельная попытка отображения сводки worker завершилась ошибкой кодировки консоли, не ошибкой analyzer; повторное чтение успешно. Первая попытка wrapper повтора была отклонена из-за взаимоисключающих timeout-аргументов до запуска процесса, evidence не перезаписывались.

Outer TAR читается один раз, выбираются один nested candidate и небольшие receipts; остальные nested candidates хешируются, не раскрываясь повторно. Nested TAR читается один раз. Результат: outer 824 записи, 878710567 байт членов, 879482880 распакованных байт; nested 2642 записи, 142009557 байт членов, 144199680 распакованных байт. ZIP ограничен 100 записями, 1 млрд байт на член и 2 млрд суммарно; outer TAR — 2 млрд распакованных байт, 50000 записей, 150 млн на член; nested TAR — 512 млн распакованных байт, 10000 записей, 100 млн на член. Выбранные bytes ограничены 150 млн на проход, JSON и lock — 10 млн, output JSON — 40 млн; JSON проверяется на повторы ключей и глубину не более 64. Память не имеет жёсткого RSS-лимита: копии данных увеличивают потребление.

Проверяются имена, коллизии, типы, checksum TAR header и padding; поддерживаются ограниченные PAX `path` и GNU longname, ссылки, sparse и неподдерживаемые типы отклоняются. Это не универсальный архивный валидатор и не защита от гонок. Исторический небезопасный инцидент и его невосстановимость задним числом сохранены в родительском отчёте; legacy scripts не запускать.
