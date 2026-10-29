# Политика лицензирования зависимостей и ограничения notices

Собственные crates рабочей области объявляют `MIT OR Apache-2.0`. Конфигурация `deny.toml` предписывает CI отклонять выражения лицензий, не входящие в явный список разрешённых, включая нераспознанные метаданные (порог уверенности также отклоняет лицензии, распознанные с низкой уверенностью). Этот список — консервативная политика автоматизации, а не юридическое заключение; до выпуска следует проверить фактическую лицензию каждой зависимости и применимые условия. Исключения для отдельных crates не настроены: при подготовке этого изменения не были проверены доказательства применимости лицензии и notices для конкретных зависимостей.

Аудит cargo-deny охватывает метаданные Cargo-пакетов и доступный ему разрешённый граф Cargo. Он не устанавливает условия лицензирования всего vendored-кода, native/static-библиотек, входных данных платформенных SDK и toolchain, сгенерированных материалов или отдельного локального SDK `resocks5`. Для них нужны отдельная инвентаризация, проверка исходных текстов, лицензий и атрибуции, а также подтверждение того, что именно линкуется или включается в поставку для каждой цели. В частности, успешное прохождение этой проверки не является юридической гарантией и не доказывает, что в бинарной поставке присутствуют все требуемые уведомления об авторских правах, тексты лицензий или файлы NOTICE.

Сейчас релизные архивы содержат только исполняемый файл; файлы контрольных сумм публикуются отдельно. Это изменение не утверждает, что полный комплект notices был сформирован или включён в поставку. Не следует называть какой-либо сформированный отчёт о зависимостях полным юридическим уведомлением, пока не проверены инвентаризация vendor/native/SDK и обязательства по notices. Аудит лицензий запускается в CI pull request и является условием сборок релиза.

## Узкий реестр native/vendor/SDK

Область: `socks5-proxy`, команда и матрица `.github/workflows/release.yml`: `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, `aarch64-apple-darwin`. Команда использует default features CLI; workspace `cargo metadata --filter-platform` из license-audit — не граф сборки CLI. Достижимость по объявлениям ниже не является доказательством фактической линковки или содержимого бинарника. Раздельного разрешённого графа features и target для CLI и linker map для этих семи сборок здесь нет.

| Компонент и область | Подтверждение и ограничения |
| --- | --- |
| SQLite, все семь целей: путь из CLI | `apps/socks5-proxy/Cargo.toml` → `arti-wrapper` → workspace `arti-client` с `static-sqlite`; `vendor/arti-client/Cargo.toml` передаёт его в `tor-dirmgr/static`, `vendor/tor-dirmgr/Cargo.toml` — в `rusqlite/bundled`. В `rusqlite-0.39.0.crate/Cargo.toml` оно включает `libsqlite3-sys/bundled`. В `libsqlite3-sys-0.37.0.crate/build.rs` bundled-ветка компилирует `sqlite3/sqlite3.c`, но переменные окружения и другие features способны изменить выбор ветки. Сам файл в архиве называет версию SQLite 3.51.3; `libsqlite3-sys` объявляет MIT для crate, что не устанавливает условия каждого файла SQLite. Нужны проверка заголовков и notices исходников и подтверждение реальной сборки. |
| ring, все семь целей: прямая зависимость CLI от `rustls` | Workspace `Cargo.toml` задаёт `rustls` с feature `ring`, которую CLI наследует. `ring-0.17.14.crate/build.rs` выбирает исходники по архитектуре и выдаёт статическую native-библиотеку; архив содержит `LICENSE-BoringSSL`, `LICENSE-other-bits`, `third_party/fiat/LICENSE`, а манифест объявляет `Apache-2.0 AND ISC`. Проверить применимость уведомлений к реально включённым частям; сам выбор feature не подтверждает конечную линковку. |
| XZ/liblzma и Zstandard: условные декларативные пути | `vendor/tor-dirmgr/Cargo.toml`: `default` включает `compression`, которая включает `tor-dirclient/xz` и `tor-dirclient/zstd`; сама зависимость `tor-dirclient` задана с `default-features = false`. В `vendor/tor-dirclient/Cargo.toml` эти features передаются в `async-compression/xz` и `async-compression/zstd`. Но workspace отключает defaults `arti-client`, а его зависимость `tor-dirmgr` отключает defaults и явно включает только `mmap`; указанные workspace features не включают `arti-client/compression`. Другие рёбра могут объединить Cargo features, поэтому активация compression для CLI и каждой цели здесь не установлена. При активации, согласно манифестам архивов evidence, `async-compression 0.4.42` → `compression-codecs 0.4.38`: XZ → `liblzma 0.4.7` → `liblzma-sys 0.4.7`; Zstd → `zstd 0.13.3` и `zstd-safe 7.2.4` → `zstd-sys 2.0.16+zstd.1.5.7`. Эти версии — из evidence, не подтверждение разрешённого графа CLI. Манифесты Rust-обёрток объявляют `MIT OR Apache-2.0`, кроме `zstd` (`MIT`) и `zstd-sys` (запись `MIT/Apache-2.0`). `liblzma-sys/build.rs` выбирает системный `pkg-config` либо компиляцию `xz/src/liblzma` в зависимости от target, feature `static` и окружения; `xz/COPYING` различает лицензии частей и указывает 0BSD для liblzma. `zstd-sys/build.rs` выбирает `pkg-config` по feature/окружению либо компиляцию `zstd/lib`; `zstd/LICENSE` содержит BSD-условия, включая уведомления при распространении бинарной формы. Не установлены активные features, выбор системных или vendored исходников и фактическая линковка. |
| OpenSSL: только кандидат | `openssl-sys-0.9.117.crate/Cargo.toml` объявляет feature `vendored` через `openssl-src`; наличие архива не доказывает ни достижимость из CLI, ни включение feature, ни системную или статическую линковку. `arti-client` имеет отдельную feature `accel-openssl`; её наличие само по себе не означает активацию. |
| Локальный SDK `resocks5-net`, все семь целей | CLI наследует path-зависимость с `default-features = false`; первичный реестр состава, происхождения и условий SDK — [ниже](#первичный-реестр-sdk-resocks5-v030). Достижимость не доказывает фактической линковки или состава поставки. |
| Платформенные SDK/toolchain | Release использует runners Linux, Windows MSVC и macOS; для двух musl-целей устанавливается `musl-tools`. Версии и лицензии фактически использованных системных библиотек, CRT, SDK и инструментов, а также статическая/динамическая линковка не установлены. Нужны provenance runner/toolchain и анализ каждого релизного бинарника. |

Доказательства архивов: `target/license-evidence-40856561166/evidence.zip`, SHA-256 `2d0c6fa6b16fe96610bd9f9b63b2387bc255ad5f86c6a735911233a3b835c7c4`; указанные пути после имени `.crate` — члены соответствующего архива внутри `archives/`. Архивы просмотрены как данные без исполнения и извлечения. Это выборочный реестр, а не полный перечень vendor/native или готовый комплект notices: необходимо отдельно установить per-target граф CLI с features, фактические build/link inputs и содержимое поставки, затем проверить лицензии и атрибуцию каждого включённого компонента.

### Уточнение первичных условий SQLite и ring

- `libsqlite3-sys-0.37.0.crate/LICENSE` — MIT для кода обёртки rusqlite: при распространении копий или существенных частей необходимо включить copyright и permission notice. Это не лицензия всего native SQLite. В `sqlite3/sqlite3.c` указан amalgamation SQLite 3.51.3 и Fossil check-in `737ae4a34738ffa0c3ff7f9bb18df914dd1c`; это декларативные сведения о происхождении, а не подтверждение фактического состава сборки; в начале вложенных `sqliteInt.h` и `msvc.h` автор отказывается от copyright и приводит благословение вместо юридического уведомления. Для частей, к которым относится этот отказ автора, сам отказ и благословение не устанавливают обязанности включать notice или текст либо иные условия распространения. Охват отказа и применимость к бинарникам неизвестны. Этот условный вывод не распространяется на весь amalgamation, другие файлы или системную SQLite; обязательства для фактически собранного native-кода требуют проверки конкретных входов и их заголовков. Фактический выбор bundled, SQLCipher или системной библиотеки и наличие кода в бинарнике не установлены.
- `libsqlite3-sys-0.37.0.crate/sqlcipher/LICENSE` содержит BSD-подобные условия: при распространении исходников сохранять copyright, условия и disclaimer; при распространении бинарной формы воспроизводить их в документации или других материалах поставки; не использовать имена для endorsement без предварительного разрешения. Эти условия следует учитывать только при использовании соответствующего SQLCipher-кода; его активация и присутствие в поставке не установлены.
- `ring-0.17.14.crate/LICENSE` различает новый код под ISC (`LICENSE-other-bits`), код BoringSSL под Apache 2.0 или ISC по заголовкам файлов и код `src/polyfill/once_cell` с отдельными `LICENSE-MIT` и `LICENSE-APACHE`. ISC требует copyright и permission notice во всех копиях; MIT — copyright и permission notice во всех копиях или существенных частях. `third_party/fiat/LICENSE` указывает Apache 2.0 и copyright авторов fiat-crypto; применимость к конкретным скомпилированным файлам следует сверить с их заголовками и выбором исходников. Наличие двух текстов once_cell само по себе не устанавливает выбор лицензии для конкретного файла.
- Apache 2.0 (`LICENSE-BoringSSL`, также `src/polyfill/once_cell/LICENSE-APACHE`) при распространении Work или Derivative Works требует дать получателям копию лицензии, явно отметить изменённые файлы, сохранить относящиеся к производной работе copyright, patent, trademark и attribution notices в распространяемой исходной форме; если Work включает NOTICE, передать относящиеся attribution notices одним из способов § 4(d). Эти условия не доказывают наличия NOTICE или применимости каждой вложенной части к конкретному бинарнику. Необходимо сопоставить заголовки, выбранные target-исходники и фактические build/link inputs до формирования notices.

### Первичный реестр SDK `resocks5` v0.3.0

**Происхождение.** `.github/actions/setup-local-sdk/action.yml` запрашивает `PHPCraftdream/resocks5` ref `v0.3.0` и переносит checkout в `../resocks5`; CLI наследует `../resocks5/crates/resocks5-net` с отключёнными default features. Проверка GitHub API 2026-10-29: [ref](https://api.github.com/repos/PHPCraftdream/resocks5/git/ref/tags/v0.3.0) указывает на аннотированный unsigned [tag object](https://api.github.com/repos/PHPCraftdream/resocks5/git/tags/2e01a96442e7d724845e7045795adc225f211160) `2e01a96442e7d724845e7045795adc225f211160`, который указывает на [commit](https://github.com/PHPCraftdream/resocks5/commit/e754abaa88ce4f9745b4729652789ffc57f8ba4c) `e754abaa88ce4f9745b4729652789ffc57f8ba4c`, tree `263db1bd209e4151eb4deadf532d423d0bf2b41c`. Это текущее разрешение изменяемого имени tag, не доказательство его неизменности во времени или авторства криптографической подписью.

Отдельное историческое свидетельство: [CI run 40856561166](https://github.com/PHPCraftdream/tor-socks5/actions/runs/40856561166), attempt 1, job `123388882161` (Cargo license policy), [прямой API лога конкретного job](https://api.github.com/repos/PHPCraftdream/tor-socks5/actions/jobs/123388882161/logs). Первичные строки checkout SDK:

```text
2026-10-29T10:24:36.8278721Z [command]/usr/bin/git log -1 --format=%H
2026-10-29T10:24:36.8321675Z e754abaa88ce4f9745b4729652789ffc57f8ba4c
```

Следовательно, этот конкретный job получил тот же commit, что и текущее разрешение tag; это не устанавливает SDK commit других job или релизов. API run сообщает `run_attempt: 1`, conclusion `failure`, а его `head_sha` относится к tor-socks5, не к SDK.

**Наблюдаемый снимок.** [GitHub API recursive tree](https://api.github.com/repos/PHPCraftdream/resocks5/git/trees/263db1bd209e4151eb4deadf532d423d0bf2b41c?recursive=1) не усечён: 237 записей, нет gitlink/submodule. [API source ZIP по commit](https://api.github.com/repos/PHPCraftdream/resocks5/zipball/e754abaa88ce4f9745b4729652789ffc57f8ba4c), локально `target/sdk-evidence-20261029/archive/sdk.zip`, SHA-256 `a923fac32bffd4234489c502493e00cbed079528d1ddedbb6960977051942ccc`, содержит 178 файлов под `PHPCraftdream-resocks5-e754aba/`. ZIP читался как данные, без извлечения и исполнения SDK. Независимая проверка сопоставила все 178 файлов ZIP с 178 blob в API tree по путям и Git SHA-1 blob ID: отсутствующих, лишних и несовпадающих файлов нет. Хеш относится к конкретно полученным байтам ZIP, а не к каноническому архиву GitHub.

При первоначальном анализе один вложенный исполнитель запустил Python без обязательного `-I`. Поэтому родительский AI-исполнитель отдельно повторил сверку через `python -I`: размер и SHA-256 ZIP, текущий tag/commit, все 178 Git blob ID и хеши четырёх копий лицензий совпали с независимо полученным GitHub tree. Исторический SDK SHA также повторно сверён с указанным job. Повторная сверка подтверждает эти данные, но не отменяет нарушения первоначальной изоляции и не доказывает линковку или полноту аудита.

**Инвентарь содержимого.** Полный список файлов доступен во внешних tree и ZIP по ссылкам выше. По расположению: 135 файлов `crates/` (исходники, README, лицензии, примеры и тесты net, а также приложение), 13 `docs/` (архитектура и reviews), 8 `tests/feature_unification/` (fixtures, конфигурация и lockfile), 7 `.github/` (шаблоны, workflows и скрипты), 15 корневых файлов (документация, лицензии, конфигурация, `Cargo.lock`, `Dockerfile`, `release.sh`). Приложение, отдельный workspace fixtures и прочие вспомогательные материалы вне `crates/resocks5-net/` присутствуют в снимке, но не входят в локальное Cargo path-замыкание net; само их наличие не доказывает включения в сборку или поставку.

**Все Cargo manifests и local path edges снимка.** Ссылки ниже закреплены commit; SHA-256 — исходные байты членов ZIP. Корневой [Cargo.toml](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/Cargo.toml), SHA-256 `53948e5f85e035db9208cff813f2b061bf0eb6fa119b5daf1e8cf3387e662229`, объявляет workspace members `crates/resocks5-net`, `crates/resocks5`, version `0.3.0`, license `MIT OR Apache-2.0`; исключает отдельный workspace `tests/feature_unification`.

| Manifest | Package / лицензия | Локальные рёбра и назначение |
| --- | --- | --- |
| [crates/resocks5-net/Cargo.toml](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/crates/resocks5-net/Cargo.toml), SHA-256 `686cd44b473d850eec48859a9491ce5e5ba4af3589f080fbacb41b5b76eb6c69` | `resocks5-net` 0.3.0, наследует `MIT OR Apache-2.0` | Нет Cargo path-зависимостей; замыкание локальных package-путей от net состоит только из него самого. |
| [crates/resocks5/Cargo.toml](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/crates/resocks5/Cargo.toml), SHA-256 `6bab3b4045ca87f29f9c39cae112448bfbc2f9f8411025e53883fca51918752e` | `resocks5` 0.3.0, наследует `MIT OR Apache-2.0` | Зависит от `../resocks5-net` с features `pool`, `tls`, `serde`, `rating`, `rotator`; dev-зависимость туда же с `test-instrumentation`. Обратной зависимости net от приложения нет. |
| [tests/feature_unification/Cargo.toml](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/tests/feature_unification/Cargo.toml), SHA-256 `8f3a41039938b995d0b05aaca292406c3e55c512d6deb6dc07f69c250fde6dea` | Отдельный workspace, не package | Members `lean-consumer`, `tls-consumer`, исключён из корневого workspace. |
| [lean-consumer/Cargo.toml](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/tests/feature_unification/lean-consumer/Cargo.toml), SHA-256 `867f28e7f2921e6a4b460a6ee9f456f75c5224093dd79036f59edde5a381a91a` | `lean-consumer` 0.0.0, `publish = false`, license не объявлена | Fixture зависит от `../../../crates/resocks5-net`, defaults выключены; не достижим из net. |
| [tls-consumer/Cargo.toml](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/tests/feature_unification/tls-consumer/Cargo.toml), SHA-256 `c8df418447e7809b8e77c16182786574ccfef51515b040700f6b1bf04bd12457` | `tls-consumer` 0.0.0, `publish = false`, license не объявлена | Fixture зависит от того же net с defaults; не достижим из net. |

Для net манифест перечисляет обычные зависимости `tokio`, `base64`, `socket2`; optional `serde`, `tokio-rustls`, `rustls`, `webpki-roots`, `dashmap`, `crossbeam-queue`; dev `anyhow`, `tokio`. Defaults — `pool`, `tls`, `serde`, `rating`, `rotator`; `pool` включает dashmap/crossbeam-queue, `tls` включает rustls/tokio-rustls/webpki-roots, `serde` включает serde, `rotator` включает `rating`. Workspace конфигурирует rustls и tokio-rustls с `ring`. Отключение defaults на одном ребре не исключает включения features другими рёбрами Cargo. Эти registry зависимости и их транзитивные native части не входят в локальное path-замыкание, их полные версии, лицензии и фактическая активация здесь не аудированы; в частности, ring — возможный внешний native input, а не доказанный результат сборки SDK.

**Native, вложенные материалы и границы поиска.** Во всех членах ZIP проверены имена `license`, `notice`, `copying` без учёта регистра, Cargo manifests, `build.rs`, признаки native-файлов и строки copyright/SPDX/license; совпадения license-имён — только два корневых текста и их идентичные копии в `crates/resocks5-net/`. Отдельного NOTICE/COPYING, каталога vendor/third_party/native, `build.rs`, C/C++/assembler-файлов, бинарных native библиотек или git submodules в этом снимке не обнаружено. Строки лицензирования вне текстов найдены в [CONTRIBUTING.md](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/CONTRIBUTING.md), корневом [README.md](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/README.md), [crates/resocks5-net/README.md](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/crates/resocks5-net/README.md) и [crates/resocks5/README.md](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/crates/resocks5/README.md); они описывают двойную лицензию. Это ограниченный поиск, не юридическая гарантия отсутствия иных условий по содержимому. В приложении `crates/resocks5/src/config/users/users_file/platform_unix.rs` есть `extern "C"`, а `platform_windows.rs` объявляет `#[link(name = "kernel32")]` и `advapi32`; тестовый `test_support.rs` также ссылается на эти библиотеки. Это системные API, не вложенные исходники; приложение не является path-зависимостью net. Происхождение, условия и фактическая линковка платформенных библиотек неизвестны.

**Первичные лицензии SDK.** [LICENSE-MIT](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/LICENSE-MIT) и [LICENSE-APACHE](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/LICENSE-APACHE) имеют соответственно SHA-256 `b9106b1c862ad319e1f2fd14a3844653938121ad9691716715292681642eeed4` и `dd167cc6194c64ee2e08ba4207aab12d75f02673a5e85be2b2a4ea9fd0dcb76b`; [копия MIT net](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/crates/resocks5-net/LICENSE-MIT) и [копия Apache net](https://github.com/PHPCraftdream/resocks5/blob/e754abaa88ce4f9745b4729652789ffc57f8ba4c/crates/resocks5-net/LICENSE-APACHE) побайтово имеют те же хеши и Git blob ID `448733073d2d7c7a95fc25f5dca33313da0cf464` и `42b6cc2b60db4659b1c808962c3eb80519d9870a`. README указывает выбор MIT или Apache-2.0. MIT требует включать copyright и permission notice во все копии или существенные части; Apache 2.0 § 4 требует копию лицензии получателям, заметные отметки изменений файлов, сохранение относящихся notices в распространяемой исходной форме и, при наличии NOTICE в Work, передачу соответствующих attribution notices; § 3 содержит патентное предоставление и условие прекращения. Apache текст включает приложение `Copyright 2026 Marat K`. Выбор альтернативы для поставки и применимость к конкретным файлам и артефактам не установлены. Полный первичный Apache-текст доступен по закреплённой ссылке выше; первичный MIT-текст сохранён ниже.

```text
MIT License

Copyright (c) 2026 Marat K

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Текст Apache 2.0 ниже воспроизведён из корневого `LICENSE-APACHE` снимка:

```text
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or Derivative
          Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work, excluding
          those notices that do not pertain to any part of the Derivative
          Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and do
          not modify the License. You may add Your own attribution notices
          within Derivative Works that You distribute, alongside or as an
          addendum to the NOTICE text from the Work, provided that such
          additional attribution notices cannot be construed as modifying
          the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright 2026 Marat K

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

**Воспроизводимость и ограничения.** Использованы `gh api repos/PHPCraftdream/resocks5`, `gh api repos/PHPCraftdream/resocks5/git/ref/tags/v0.3.0`, `gh api repos/PHPCraftdream/resocks5/git/tags/2e01a96442e7d724845e7045795adc225f211160`, `gh api repos/PHPCraftdream/resocks5/git/commits/e754abaa88ce4f9745b4729652789ffc57f8ba4c`, `gh api 'repos/PHPCraftdream/resocks5/git/trees/e754abaa88ce4f9745b4729652789ffc57f8ba4c?recursive=1'`, `gh api repos/PHPCraftdream/tor-socks5/actions/runs/40856561166`, `gh api repos/PHPCraftdream/tor-socks5/actions/runs/40856561166/jobs --paginate`, `gh api repos/PHPCraftdream/tor-socks5/actions/jobs/123388882161/logs`, API ZIP по ссылке выше, `python -I target/sdk-evidence-20261029/analysis/inspect.py` и `python -I target/sdk-evidence-20261029/analysis/summary.py`. Проверка не использовала cargo metadata, сборку, тесты или исполнение SDK. Этот реестр покрывает снимок и локальные path-рёбра, не полный транзитивный crates audit, linker map, системные SDK или готовый комплект notices.

### Локальные overrides в `vendor/`

Корневой `[patch.crates-io]` перечисляет семь локальных путей; `vendor/README.md` описывает их как модифицированные копии и указывает базу Arti 0.47.0, синхронизацию 2026-10-13. Патч разрешает подмену соответствующей версии, но сам по себе не доказывает использование пакета конкретной сборкой. Версии и выражения ниже — из локальных `Cargo.toml`, а не вывод о лицензии каждого файла:

| Локальный crate | Версия | Объявленная лицензия | Назначение локальных изменений по `vendor/README.md` |
| --- | --- | --- | --- |
| `arti-client` | 0.47.0 | MIT OR Apache-2.0 | readiness guard, recovery API, повтор подключения |
| `tor-chanmgr` | 0.47.0 | MIT OR Apache-2.0 | закрытие каналов, timeout транспорта |
| `tor-circmgr` | 0.47.0 | MIT OR Apache-2.0 | выбор путей и длина circuits |
| `tor-dirclient` | 0.47.0 | MIT OR Apache-2.0 | idle timeout и проверка длины тела |
| `tor-dirmgr` | 0.47.0 | MIT OR Apache-2.0 | timeout и восстановление bridge, обработка ошибок SQLite |
| `tor-guardmgr` | 0.47.0 | MIT OR Apache-2.0 | readiness и восстановление guard/bridge |
| `saturating-time` | 0.5.0 | MIT OR Apache-2.0 | отложенное вычисление пределов |

Комментарий корневого `Cargo.toml` называет `saturating-time` 0.3.0, но локальный манифест и `vendor/README.md` указывают 0.5.0. README также отдельно сообщает, что `ptrs-gesher` не vendored. Этот реестр ограничен семью overrides, а не всеми транзитивными исходниками. Манифестные выражения не заменяют проверку заголовков, авторства, текстов лицензий, локальных изменений и данных `tor-dirmgr/testdata`; наличие и полнота соответствующих license/notice-файлов и применимость обязательств при распространении исходников или бинарников к конкретным материалам не установлены. Нужны сверка происхождения копий с upstream и выбор применимой лицензии, а также per-target подтверждение их использования и комплект notices.

### Уточнение provenance и условий overrides

Семь локальных `.cargo_vcs_info.json` декларируют один upstream SHA `ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087`; соответственно `path_in_vcs`: `crates/arti-client`, `crates/tor-chanmgr`, `crates/tor-circmgr`, `crates/tor-dirclient`, `crates/tor-dirmgr`, `crates/tor-guardmgr`, `crates/saturating-time`. Это декларативные сведения о происхождении, не доказательство неизменности, совпадения с upstream или включения в бинарник; README прямо описывает локальные изменения.

Для каждого из семи манифест объявляет альтернативу `MIT OR Apache-2.0`, а не одновременно обе лицензии. При выборе MIT для соответствующего кода условие — включить copyright и permission notice во все копии или существенные части; при выборе Apache 2.0 действуют условия § 4, изложенные выше, включая условный NOTICE и отметки изменённых файлов. Первичные тексты условий: локальные `LICENSE-MIT` и `LICENSE-APACHE` в корне workspace; их наличие в корне не доказывает, что они относятся ко всем отдельным файлам overrides. В рекурсивном просмотре семи каталогов по именам, содержащим `license` или `copying`, либо равным `NOTICE`, таких файлов не обнаружено; это не исключает уведомления под другими именами или в содержимом файлов. Заголовки, авторство, выбор альтернативы, происхождение и условия `tor-dirmgr/testdata` требуют отдельной проверки; условия для релизного бинарника остаются неизвестными до подтверждения состава и применимости.

## Выявленные условия и открытые вопросы

По Cargo metadata для семи поддерживаемых целей из `socks5-proxy` достижимы `colored` и `option-ext` с `MPL-2.0`, а также `priority-queue` с `LGPL-3.0-or-later OR MPL-2.0`. Достижимость в метаданных не доказывает, что каждый пакет входит в бинарник: граф может содержать build-зависимости и не отражает точный результат линковки. Для соответствующего кода под MPL при распространении исполняемой формы требуется предоставить получателям информацию о доступе к исходному коду согласно [разделу 3.2 MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/); условия распространения исходного кода и сохранения уведомлений установлены разделами 3.1 и 3.4.

В том же графе присутствуют `webpki-roots` с `CDLA-Permissive-2.0`. При распространении материала, подпадающего под соглашение, [раздел 2.1 CDLA](https://cdla.dev/permissive-2-0/) требует предоставить получателям текст соглашения. Применение этого условия к конкретному релизному артефакту и его данным ещё не установлено.

Необходимо проверить точный состав каждой сборки, исходные пакеты и их уведомления, документировать выбор применимой альтернативы для `priority-queue` и обеспечить соответствующие тексты и доступ к исходникам. Эти сведения не являются юридическим заключением; до завершения проверки отклонённые лицензии не добавляются в allowlist.
