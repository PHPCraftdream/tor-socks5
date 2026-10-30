# Компоненты release candidate run 40934653900

## Статус: PARTIAL

Аналитический отчёт по ограниченному доступному evidence подготовлен; статус остаётся PARTIAL.
Это не завершённый анализ состава или разрешение релиза.
Подтверждены аутентифицированные метаданные API и независимо повторённый размер и SHA-256 локального ZIP; production origin не подтверждён.
Сохранённые data-only inventory, primary и binary запуски завершились с exit 0; остальные 714 `.crate` не проверены.
Финальный повтор binary завершился с exit 0; исправленное представление Darwin frameworks показывает IOKit, CoreFoundation и SystemConfiguration, а не `Versions`.
Ранние локальные журналы получены небезопасным анализом архивов и не являются самостоятельной проверкой.
Полные native inputs, юридические reviews и production origin остаются открыты.
Остаются незавершёнными анализ состава и обязательств, reviews и проверка production origin.

## Идентификация и уровень доверия

- Run: `40934653900`; событие PR, attempt `1`, результат `success`.
- Точный SHA головы PR: `ff8a4253b1b632a50d45d91bbe23fa86d2a7f5bc`.
- Аутентифицированные метаданные API подтверждены по предоставленным данным.
- Artifact API ID: `12932028389`; размер `853866809` байт.
- SHA-256 из API: `75a58bb9393525b64f083105113771680bb561e1ff2f28f337fa584954b847d4`.
- Локальный ZIP независимо подтверждён: 853866809 байт и тот же SHA-256, что в API.
- [Run API](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/runs/40934653900); [artifact API](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12932028389).
- Retained artifact `12931503823` не скачан и его байты не исследованы.
- Семь binary ZIP скачаны; их наличие не доказывает состав и происхождение.
- Запуск PR, даже успешный, не является доверенной production authority.
- Наличие диаграмм, checksum или receipt не заменяет проверку origin.
- Аутентифицированные API-данные устанавливают PR merge ancestry: source commit `67f82c1e107ab24e8fd22afb9fd12134ffa7f982`, tree `8c5be9171f2a2fa0f83dc42a60d9bb731d891d4c`; родители `b4a27a0cb806ce4efeef23aa94b375ce2f4222d1` и `ff8a4253b1b632a50d45d91bbe23fa86d2a7f5bc`.
- Сообщение merge: `Merge ff8a4253b1b632a50d45d91bbe23fa86d2a7f5bc into b4a27a0cb806ce4efeef23aa94b375ce2f4222d1`. Run PR attempt 1, head `ff8a4253b1b632a50d45d91bbe23fa86d2a7f5bc`, workflow `400677266`, `.github/workflows/license-bundle.yml`.
- [Commit API](https://api.github.com/repos/PHPCraftdream/tor-socks5/git/commits/67f82c1e107ab24e8fd22afb9fd12134ffa7f982), [PR API](https://api.github.com/repos/PHPCraftdream/tor-socks5/pulls/33), [run API](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/runs/40934653900), [workflow API](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/workflows/400677266).
- Новый inventory сообщает совпадение самохеша project commit `67f82c1e107ab24e8fd22afb9fd12134ffa7f982`, tree `8c5be9171f2a2fa0f83dc42a60d9bb731d891d4c` и двух родителей выше; SDK commit `e754abaa88ce4f9745b4729652789ffc57f8ba4c` также совпал, SDK tree `263db1bd209e4151eb4deadf532d423d0bf2b41c`. Это наблюдение proof отдельно от подтверждённой предоставленными API-данными merge ancestry.
- Самохеш commit из proof не равен проверке source bytes по доверенному GitHub tree; такая проверка ещё не выполнена. Ни она, ни ancestry не устанавливают production authority.
- Новый SOCKS-код и vendor warning patch PR #30 не входят в рассматриваемую сборку; этот анализ не авторизует будущий объединённый release.

## Использованные материалы

- Описание процесса: `release-bundle.md`.
- Исторический анализ: `license-evidence-40856561166-analysis.md`.
- Прочитанные фрагменты контрактов: `.github/release/license/admission.py` строки 1–180 и `.github/release/license/bundle.py` строки 1–90.
- Описание origin и SDK: `docs/project/license/release-bundle.md`, строки 18–30.
- Защищённый журнал повторного анализа: `target/stage1-analysis-data-20261029/analysis.log`.
- JSON-записи журнала прочитаны отдельно data-only Python `-I`, без исполнения project code.
- Сохранённые диагностические журналы: `inventory.txt`, `all-targets.txt`,
  `binaries-and-graphs.txt`; их прежний способ разбора не считается безопасным.
- Исторический анализ восьми пакетов относится к другому run и другому набору bytes.
- Его собственная оговорка: происхождение старого ZIP независимо не установлено.
- Перенос правовых вопросов допустим; перенос подтверждения состава — нет.
- Архивы проверены ограниченными локальными скриптами; данный шаг читал только сводку как данные.
- Тесты, сборки и валидаторы проекта не запускались.

## Семь целей: проверенные бинарные bytes

Наблюдавшийся сохранённый `verify-safe-binaries.py` с `python -I` дал exit 0:
семь совпадений receipt, все true; graph counts соответствуют таблице ниже. Финальный повтор после исправления формата Darwin завершился с exit 0; frameworks: IOKit, CoreFoundation и SystemConfiguration, не `Versions`.
Для каждого скачанного ZIP проверены размер и SHA-256 по закреплённым значениям;
вложенный executable имеет указанные bytes и совпадает с `binary_sha256` receipt.
Это проверка совпадения bytes, не доказательство состава, origin или compliance.

| Target | Artifact ID | ZIP байт | ZIP SHA-256 |
| --- | --- | ---: | --- |
| `aarch64-apple-darwin` | [12931773573](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12931773573) | 12126824 | `bcf0edb870c0dfeb1ec71bf6262328885226ae489ddd81a6493277bde63b78f8` |
| `x86_64-apple-darwin` | [12930598391](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12930598391) | 12678740 | `351d145d890ee0d8a7de555af7a2e176c693c5a621636ba0a669e571cb7af8fd` |
| `x86_64-pc-windows-msvc` | [12929435820](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12929435820) | 12747241 | `807a36536fc8c7558829dc3c1ba89a6f22579307c6a3a8e0e0d34cf76531b393` |
| `aarch64-unknown-linux-musl` | [12927756356](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12927756356) | 12982288 | `46861aea32f692039d5d5ce4286265a15c1adcf3244e2e8b4de0a8c78bbc9025` |
| `aarch64-unknown-linux-gnu` | [12926432069](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12926432069) | 13007952 | `8d6909f2f42b902bdced58f91cd1a96559da5a0ed08b31f1835e88657d35803c` |
| `x86_64-unknown-linux-gnu` | [12925166590](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12925166590) | 13223590 | `fd759bd0516de84edb2b3599fc3389d8240947fa228d10a27913ad4bc6506d87` |
| `x86_64-unknown-linux-musl` | [12924449353](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/artifacts/12924449353) | 13473713 | `bc92c80fa638e9ef5f1fe77b6f7dfcadc8f2b16ec5bc4a6e2777685cda2f4c44` |

| Target | Binary байт | Binary SHA-256 / receipt match |
| --- | ---: | --- |
| `aarch64-apple-darwin` | 36355568 | `e452ccd04ab22cd614f29dbdd1ebce4952f13db9a61370e5c751db9e06e90de4` |
| `x86_64-apple-darwin` | 37581112 | `507e1c1349837eb7e52eb4a87002e02ee7ab8e209ddbb25f3c0031849132a326` |
| `x86_64-pc-windows-msvc` | 36523520 | `132cf698d1841cfe4123abc95e891e9e60153d893fb46a4ba5a5b505c7090746` |
| `aarch64-unknown-linux-musl` | 39124368 | `78e051c957228fea7f719d394f6827d0d50e06691d9f725ffb488692521e9673` |
| `aarch64-unknown-linux-gnu` | 39885872 | `3e263cdeab6638502e83fdb89cb7878623592f177b450e49dc25fac1cbc4efe8` |
| `x86_64-unknown-linux-gnu` | 40749864 | `f8ee9ffd9a58e0578f92b2c6df84a5754bcfb9b61c5bf3d6895dc5e48baf0ab1` |
| `x86_64-unknown-linux-musl` | 40647872 | `2b2184d890ca902c286039ef19a9eae863528ce4fb363cfa3a6c6ce5cfa4bd66` |

Общие assertions receipt: `source_digest` = `f8f9612d0bb2fb090da68a0722a401bf5b94312f86a7724922019c76a6c3fc44`,
`SDK commit` = `e754abaa88ce4f9745b4729652789ffc57f8ba4c`, tag `v0.0.0-license-ci`.
Source digest и build evidence digest не пересчитаны этой бинарной проверкой.

| Target | `build_evidence_digest` из receipt, не пересчитан |
| --- | --- |
| `aarch64-apple-darwin` | `447d139cf97c5317e5414003d630c076bab577d00e57eea4bdc66a4d8358f2e5` |
| `x86_64-apple-darwin` | `9d8b22c09090993f898ddd5f9b4133e80973dd54c8058c44dbef4013df855a1e` |
| `x86_64-pc-windows-msvc` | `6b298fdf8a35f45718bae4a2afd8e1bdc414f310fd7cd3abf4405af01212fe1e` |
| `aarch64-unknown-linux-musl` | `d8ebedeadce1b4847e3a0b406e39e9201c6824191603e45b13d917d26fa24a3e` |
| `aarch64-unknown-linux-gnu` | `e36c10caae8c10defe9bbf494119a9512618f98682763b9904d08fb22ae6ac6c` |
| `x86_64-unknown-linux-gnu` | `f322276ca62c2a711fb028bdda2be89b0b75089c4b7ee7ab0a26d7a5197fa703` |
| `x86_64-unknown-linux-musl` | `09fbda25cf92becce41c2e46b33a8a43b57daae0189aabd7fe992ecd29f9e830` |

### Cargo messages и сохранённая диагностика linkage

Числа — compiler-artifact / уникальные package ID / build-script-executed;
каждый граф также содержит одно `build-finished`. Это не бинарный linker trace.

| Target | Три числа | `linked_libs` из build-script-executed |
| --- | --- | --- |
| `aarch64-apple-darwin` | 574 / 503 / 44 | ring, sqlite3, SystemConfiguration |
| `x86_64-apple-darwin` | 572 / 504 / 43 | ring, sqlite3, SystemConfiguration |
| `x86_64-pc-windows-msvc` | 592 / 521 / 46 | ring, sqlite3, winapi, iphlpapi |
| `aarch64-unknown-linux-gnu` | 569 / 499 / 43 | ring, sqlite3 |
| `aarch64-unknown-linux-musl` | 569 / 499 / 43 | ring, sqlite3 |
| `x86_64-unknown-linux-gnu` | 567 / 500 / 42 | ring, sqlite3 |
| `x86_64-unknown-linux-musl` | 567 / 500 / 42 | ring, sqlite3 |

Во всех графах ring 0.17.14 сообщает `static=ring_core_0_17_14_` и
`static=ring_core_0_17_14__test`; libsqlite3-sys 0.37.0 сообщает `static=sqlite3`.
На Apple system-configuration-sys сообщает `framework=SystemConfiguration`.
На Windows ipconfig сообщает `iphlpapi`, winapi сообщает `dylib=` для
advapi32, cfgmgr32, credui, gdi32, kernel32, msimg32, ole32, opengl32,
secur32, shell32, user32 и winspool. Это directives, не доказанные PE imports.
Сообщение build script не доказывает, что все перечисленные библиотеки оказались в binary.
`openssl-src` и `zstd-sys` присутствуют как source candidates; в этих выбранных графах
соответствующие compiler artifacts не указаны, их нельзя объявлять слинкованными.

Отдельно сохранённый `linkage.txt` сообщает для GNU NEEDED libgcc_s, libm,
libc и соответствующий ld-linux; для aarch64 musl — нет dynamic section,
для x86_64 musl — dynamic section без перечисленных NEEDED; для обеих Apple целей —
IOKit, CoreFoundation, SystemConfiguration, iconv и System.
Для Windows readelf сообщает ошибку «не ELF»: он непригоден для анализа PE.
Независимый разбор platform imports для всех целей отсутствует; binaries не исполнялись.
Даже сохранённый `linkage.txt` — диагностика, а не полный static/native input trace.

## Проверенный ограниченный inventory исходников

Сохранённый `analyze-safe.py` с поддержкой GNU longname завершился с exit 0; его inventory содержит 736 компонентов и 743 blockers.
Подтверждённый локальный ZIP совпадает по размеру и SHA-256 с API metadata.
Outer: 824 записи, сумма размеров членов 878710567 байт, распакованный поток 879482880 байт.
Все семь nested candidate имеют размер 120341965 и одинаковый SHA-256:
`c2787211e957ac6e1cac1d0b2fbf34e24cd0444b835febed8aef63e7e9dafa5e`.
Один nested inventory: 2642 записи, сумма размеров членов 142009557 байт,
распакованный поток 144199680 байт. Совпадение hash не доказывает binary composition.

Подсчёт строго по префиксам путей вложенного candidate:
- `sources/.../registry/`: 727 записей; `candidates/`: 1212 записей.
- `project/`: 518, в том числе `project/vendor/`: 162; без vendor: 356.
- `sdk/`: 178. Всего по этим префиксам: 2635 записей.
- Строковые метки журнала `contains_registry` = 733 и `contains_candidate` = 1214
  не являются категориями путей: они считают вхождения подстрок в любых именах.
- Аналогично `contains_source` = 2638 не означает 2638 исходных файлов.
- Из 727 registry `.crate` отдельно проверены внутренности 13 выбранных; 714 не исследованы.

### MANIFEST, blockers и информация получателю

- `MANIFEST.json`: 736 компонентов по префиксам ID: 727 registry, 7 vendor,
  1 project и 1 sdk; отдельного поля `kind` в этих записях нет.
- `BLOCKERS.json`: 743 записи; missing attributable notice для всех семи vendor:
  `arti-client`, `saturating-time`, `tor-chanmgr`, `tor-circmgr`,
  `tor-dirclient`, `tor-dirmgr`, `tor-guardmgr`.
- Отсутствуют component reviews, в том числе для project, sdk и registry.
- `REVIEWS.json`: `components: {}`; это не юридическое одобрение.
- `SOURCE-INFO.txt` указывает тестовый tag и путь к исходникам в candidate;
  он прямо предупреждает, что inventory не доказывает linkage и ссылка не гарантирует сохранность.
- Собственная лицензия проекта `MIT OR Apache-2.0` не лицензирует автоматически зависимости.
- Наличие исходников, notices и candidate texts не доказывает включение в binary,
  полноту corresponding source, права третьих лиц или выполнение обязательств.

### Примеры сохранённых candidate texts

Ниже SHA-256 сохранённых файлов; 13 выбранных `.crate` теперь отдельно проверены.
Для восьми ранее изученных пакетов первичные hashes совпадают с таблицей и прошлым анализом;
это не подтверждает состав бинарника и не означает автоматического approval.

| Пакет и файл | SHA-256 |
| --- | --- |
| `colored-2.2.0/LICENSE` | `fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85` |
| `option-ext-0.2.0/LICENSE.txt` | `66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172` |
| `priority-queue-2.7.0/LGPL-3.0-or-later.txt` | `da7eabb7bafdf7d3ae5e9f223aa5bdc1eece45ac569dc21b3b037520b4464768` |
| `priority-queue-2.7.0/MPL-2.0.txt` | `c73cc0c27b0f24d5612e76bf83b5845c4fbd0374a1a8483f3d16befe58a60c9a` |
| `webpki-roots-0.26.11/LICENSE` | `e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8` |
| `webpki-roots-1.0.7/LICENSE` | `e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8` |
| `xxhash-rust-0.8.18/LICENSE` | `c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566` |
| `async_executors-0.7.0/LICENSE` | `88d9b4eb60579c191ec391ca04c16130572d7eedc4a86daa58bf28c6e14c9bcd` |
| `notify-8.2.0/LICENSE-CC0` | `e0456cbab4f7b5e7203e678faff37eadbdfef02e822db3b7a52a1dd9d3dc514a` |
| `ring-0.17.14/LICENSE` | `b3d734001a94efff3579978d953391aa7115f877657d25eb54037a43875d078a` |
| `ring-0.17.14/LICENSE-BoringSSL` | `005fc765ddc5115da796cca915baa9557abae13ff35e0a47c47affc56f6c414d` |
| `ring-0.17.14/LICENSE-other-bits` | `f025ccfb7dfb6bdfedc75ca0f67acc69e6fb4998143d834f7c2f38a29989680f` |
| `openssl-src-300.6.1+3.6.3/openssl/LICENSE.txt` | `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a` |
| `liblzma-sys-0.4.7/xz/COPYING` | `616a3ad264ce29b8f1cb97e53037b139d406899ca8d1f799651e17bfa09830b8` |
| `zstd-sys-2.0.16+zstd.1.5.7/zstd/LICENSE` | `7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8` |

У native candidates имеются и другие тексты; эти примеры не исчерпывают их права и notices.

## Условные лицензионные обязательства

Ниже описаны вопросы при соответствующем распространении, а не итог review.
Версии и условия сопоставлены с выбранными первичными файлами текущего candidate.
Все восемь ранее изученных пакетов присутствуют как `compiler-artifact` типа `lib`
во всех семи проверенных Cargo-графах; build graph не доказывает итоговую линковку.

### MPL-2.0: colored и option-ext

- Исторический анализ указывает `colored 2.2.0` и `option-ext 0.2.0`.
- При применимости MPL §§3.1–3.4 сохранить применимые notices и текст лицензии.
- Распространяемый covered source и изменения предоставить на условиях MPL.
- Для executable сообщить, как получить соответствующий covered source.
- Способ должен быть разумным; плата не выше стоимости распространения.
- Установить конкретные covered файлы, изменения и долговременную доступность.
- Ни включение в binary, ни достаточность исходников здесь не установлены.

### priority-queue: выбор альтернативы

- Исторический `priority-queue 2.7.0`: `LGPL-3.0-or-later OR MPL-2.0`.
- Какая ветвь выбрана для конкретного распространения, не установлено.
- Если применима выбранная MPL, оценить обязательства §§3.1–3.4 выше.
- Если выбрана LGPL и распространяется Combined Work, оценить §4 целиком.
- Нужны применимые notices, копии LGPL и GPL и разрешённые права модификации.
- По §4(d)(0) обеспечить Minimal Corresponding Source и Application Code,
  позволяющие перекомпоновку на предусмотренных условиях, либо по §4(d)(1)
  использовать соответствующий совместимый механизм разделяемой библиотеки.
- Installation Information по §4(e) требуется только при установленных условиях GPL §6.
- Вариант и работоспособность замены или перелинковки не проверены.
- Внутри выбранного crate единственный GPL-именованный путь — LGPL-текст;
  отдельный GPL-именованный файл не найден в этом crate, не во всём bundle.
- Общий `NOTICES.txt` может содержать GPL от других компонентов; его отсутствие не утверждается.
- При необходимости текст GPL и применимые материалы нужно обеспечить и проверить.

### webpki-roots, CDLA и CCADB

- Исторический анализ рассматривает версии `0.26.11` и `1.0.7`.
- В нём 0.26.11 переэкспортирует данные родительской зависимости;
  1.0.7 содержит исходную таблицу trust anchors и комментарии к сертификатам.
- Наличие исходников не доказывает наличие этих данных в конкретном binary.
- CDLA-Permissive-2.0 §2.1: при sharing Data текст соглашения доступен с Data.
- §3.1 не налагает ограничений или обязательств на Results.
- Является ли конкретный распространяемый материал Data или Results, неизвестно.
- Исторический анализ приводит требование атрибуции на странице CCADB,
  отдельно от текста CDLA; применимость и условия конкретного получения неизвестны.
- Выяснить происхождение, атрибуцию, notices и запрет подразумеваемого endorsement.
- В текущем `NOTICES.txt` найдено 10 совпадений `CCADB`, включая исторический анализ;
  это не доказательство достаточной атрибуции, но и не её полное отсутствие.
- [Условия CCADB](https://www.ccadb.org/rootstores/usage#ccadb-data-usage-terms) и
  [текст CDLA](https://cdla.dev/permissive-2-0/) оценивать отдельно.
- Бинарное наличие самих данных не наблюдалось при этой проверке.
- Само преобразование данных не доказывает классификацию Results.

### Прочие исторические записи

- `xxhash-rust 0.8.18`: BSL-1.0; учитывать исключение для machine-executable object code.
- Для исходных копий сохранить соответствующие copyright и текст лицензии.
- `async_executors 0.7.0`: Unlicense; оценить права третьих лиц и notices.
- `notify 8.2.0`: CC0-1.0; патенты и товарные знаки отдельно от отказа от прав.
- Для каждого сначала установить распространяемый материал и отдельные условия файлов.

## Первичные native материалы выбранных crate

Сохранённый `inspect-primary.py`: exit 0, 13 crates, 12 project/SDK license files и 10 строк с CCADB.
Он проверил отдельные файлы и ограниченные excerpts внутри 13 архивов,
но не установил доступность исходников получателю или полную линковку.

- `ring-0.17.14/LICENSE`, SHA-256 `b3d734001a94efff3579978d953391aa7115f877657d25eb54037a43875d078a`, строки 1–5:
  новые файлы ISC, отдельные материалы BoringSSL — Apache-2.0; `LICENSE-other-bits`
  содержит ISC notice, а `LICENSE-BoringSSL` — Apache текст. Сохранить применимые notices;
  наличие build-script directives не доказывает включение каждого файла в executable.
- `libsqlite3-sys-0.37.0/LICENSE`, SHA-256 `c10c1f27337546471e5f7e4e97fdd398b35b9d4e126115dcd22de8d8e65abf6f`,
  содержит MIT-разрешение wrapper с copyright rusqlite developers.
  `sqlite3/sqlite3.c`, SHA-256 `9512509b1bccb7461f79bea8aad6280ae4699e925fa4804381b71f59e7efb0c5`,
  содержит заявление SQLite о public domain; оно не устанавливает автоматически права на wrapper,
  SQLCipher, сторонние файлы или происхождение реально использованного исходника.
  Build script сообщает `static=sqlite3`, но точные native bytes ещё надо связать со сборкой.
- `liblzma-sys-0.4.7/xz/COPYING`, SHA-256 `616a3ad264ce29b8f1cb97e53037b139d406899ca8d1f799651e17bfa09830b8`,
  строки 5–8: разные файлы имеют разные условия, liblzma указан как 0BSD.
  В архиве также есть GPL и LGPL тексты: нельзя слепо применять root license ко всему дереву.
- `zstd-sys-2.0.16+zstd.1.5.7/zstd/LICENSE`, SHA-256 `7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8`, — BSD;
  `zstd/COPYING`, SHA-256 `f9c375a1be4a41f7b70301dd83c91cb89e41567478859b77eef375a52d782505`, — GPL.
  Документацию об альтернативных условиях оценивать по конкретным файлам; пока это source-only evidence.
- `openssl-src-300.6.1+3.6.3/openssl/LICENSE.txt`, SHA-256 `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`,
  содержит Apache-2.0 для исходников OpenSSL 3.6.3; вложенные сторонние файлы могут иметь иные условия.
  Это source-only evidence, не утверждение о включении OpenSSL в binary.

## SDK, vendor и platform inputs

- SDK commit по описанию процесса: `e754abaa88ce4f9745b4729652789ffc57f8ba4c`, отдельно от project commit.
- SDK root `LICENSE-APACHE`: `dd167cc6194c64ee2e08ba4207aab12d75f02673a5e85be2b2a4ea9fd0dcb76b`.
- SDK root `LICENSE-MIT`: `b9106b1c862ad319e1f2fd14a3844653938121ad9691716715292681642eeed4`.
- Оба файла присутствуют также у `resocks5-net`; это не устанавливает условия каждого файла.
- Семь vendor с missing attributable notices перечислены выше; их source files присутствуют,
  но наличие исходников не разрешает вопрос пофайлового авторства и notices.
- Нужно установить точные SDK bytes, происхождение, изменения и условия распространения.
- Git proof показывает согласованность bytes, но не доверенное production origin.
- Для vendor проверить происхождение, авторство, notices и каждый затронутый файл.
- Системные библиотеки и SDK зависят от платформы и конкретной toolchain.
- Нужны точные версии, источники, права и применимые условия поставки.
- Статические библиотеки и генерируемые native inputs требуют отдельного trace.
- Build logs и output hashes — диагностика, а не полный перечень linker inputs.

## Контракт component и target review

- Component review связывает `source_digest` и `selected_license`.
- Нужны непустые обоснование `rationale` и `obligations`.
- Списки `notices`, `evidence`, `retained_notices`, `corresponding_source`
  содержат ссылки на payload и SHA-256 соответствующих байтов.
- Сохранение всех candidate texts не означает принятие юридического решения.
- Для vendor без candidate texts необходима пофайловая attribution review.
- Поддерживаемый кодом набор лицензий ограничен; MPL, CDLA и LGPL блокируются.
- Привязка bytes не доказывает полноту обязательств и не создаёт review.
- Component digest проекта исключает review control для устранения цикла.
- Общий receipt `source_digest` включает исходные bytes, modes и Git proof.
- Поэтому эти две identity нельзя считать одним и тем же digest.

Target review привязывается к четырём значениям identity:
`source_digest`, `binary_sha256`, `target`, `build_evidence_digest`.
Для каждого target нужны четыре отдельные категории evidence:

1. `native-link-inputs` — фактические native и static inputs.
2. `platform-toolchain-inputs` — происхождение и условия платформы и toolchain.
3. `build-input-correspondence` — соответствие исходников, сборки и бинарных bytes.
4. `recipient-source-availability` — доступность необходимых исходников получателю.

Для каждой категории нужны path, sha256, obligations и reviewer rationale.
Отсутствие evidence остаётся blocker; формальная привязка не заменяет review.
Ни component reviews, ни target reviews здесь не утверждаются как одобренные.

## Инцидент и хронология

Изначально artifact скачали в `stage1-data-20261029/` в корне worktree, а scripts записали в соседний `stage1-scripts-20261029/`; это было вне разрешённого `target/`. `inventory.py`, `inspect.py` и `inspect-target.py` выполнили до требуемых hardened limits: это несоблюдение требований безопасной обработки недоверенных архивов. Затем собственные каталоги перенесли под `target/`, но последующее перемещение и hardened repeat не исправляют нарушение задним числом. Небезопасные legacy-процедуры больше никогда не запускать; evidence и журналы сохранены.

Первый запуск нового analyzer отказал на виртуальном PAX-маркере `././@PaxHeader`; добавлена точная поддержка только этого metadata-маркера. Новые primary запуски a/b отказали на GNU longname `L` размером 102 в OpenSSL. Добавлена ограниченная поддержка `L` до 513 байт с одним завершающим NUL и проверкой пути; `K`, ссылки и sparse по-прежнему запрещены, проверки типов и путей не ослаблены. Неудачные outputs a/b сохранены как evidence; последующий inventory с GNU L завершился с exit 0.

## Воспроизведение ограниченных проверок

Сохранённый toolkit из трёх scripts и полная инструкция получения восьми ZIP: [README](release-components-40934653900-repro/README.md). Прежние локальные scripts и их hashes относятся только к истории, не являются требуемыми инструментами воспроизведения. Новые scripts выполняются как доверенный код с `python -I`, без imports проекта; финальные SHA-256 приведены в README.

Для анализа выбран candidate ZIP размером 853866809 байт и семь binary ZIP общим размером 90240348 байт вместо retained размером 943666915 байт; retained не исследован.

Наблюдавшиеся результаты: `target/repro-saved-inventory-20261029-d/inventory.json` — 824 outer, 2642 nested, 736 компонентов, 743 blockers; `target/repro-saved-primary-20261029-c/primary.json` — 13 crates, 12 project/SDK файлов-кандидатов по имени (6 `LICENSE-*` и 6 workflow/аналитических файлов, не первичные лицензии), 10 строк CCADB; `target/repro-saved-binaries-20261029-c/summary.json` — семь совпадений receipt, все true, graph counts как выше. Все три запуска exit 0. Команды и безопасные свежие имена для повторов приведены в README.

## Минимальные следующие действия

1. Расширить безопасный анализ на остальные 714 `.crate` и недостающие evidence;
   проверить native/static inputs и embedded data, не выводя их из графа.
2. Использовать проверенные совпадения binary и receipt; retained bytes получить и проверить,
   если это понадобится для production proof; пересчитать source и build evidence digests.
3. Установить native и platform inputs, состав и доступные исходники;
   после этого провести component, target и необходимые юридические reviews.
4. Только затем проверить доверенный production origin и всю цепочку admission
   по правилам защищённого main, policy SHA, API и точным artifact ID.
5. До устранения всех блокеров не создавать tag и не выпускать релиз.

**Итог: PARTIAL.** Доказательств состава, compliance и production authority недостаточно.
