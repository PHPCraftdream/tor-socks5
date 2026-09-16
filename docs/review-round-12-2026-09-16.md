# Ревью tor-socks5 — раунд 12

Дата: 2026-09-16. Проверены ревизии `3c433d8..be395f9`, включая `408a840` и `be395f9`, а также текущее дерево на `be395f9`. Это ручное целевое ревью; оно не является доказательством исчерпывающей проверки всех vendored Arti-путей.

## Объём и результат

Последние изменения проверены отдельно: передача исходного PT executable в Android APK; эксклюзивные batch/check scratch-каталоги; жизненный цикл throwaway runtime; очистка PT по `TOR_PT_STATE_LOCATION` с повторной проверкой окружения и pidfd; Android MAIN с первым exit CONNECT на 4 секунды и одним повтором на обычные 10 секунд. Проверены также JNI/engine shutdown и callback-пути, `arti-wrapper`/vendored `arti-client`, bridge fetch/probe/store/config, DNS cache, auth, SOCKS5 concurrency, upstream и resource bounds.

В последней серии изменений новых дефектов не подтверждено. В общем текущем коде были подтверждены два P2 и один P3; все существовали до последних Android-коммитов и теперь исправлены. TS12-01 фиксировал ограничение конкурентных записей; прежний TS2-01 о полностью последовательных записях уже был исправлен и здесь не переоткрывался.

| ID | P | Задача | Статус |
|---|---|---|---|
| TS12-01 | P2 | Сохранять CLI-мутацию при пересечении с daemon publish | Закрыта; per-path advisory lock |
| TS12-02 | P2 | Согласовать конкурентные изменения CandidatePool | Закрыта; транзакционная блокировка |
| TS12-03 | P3 | Проверять уже буферизованный EOF-body относительно лимита | Закрыта; pre-read cap check |

Исправления: общий `PathLock` на sibling `.lock` файле сериализует полный
load→mutate→save для daemon и CLI; CandidatePool удерживает его через probe
и сохраняет удаления без blind merge; HTTP reader проверяет уже buffered body
до EOF-read. Добавлены детерминированные overlap и boundary regression tests.

## Последние изменения

### Подтвержденных дефектов нет

`main_engine_settings` действительно прокидывает `initial_connect_timeout=4s`; `TorClient::connect_with_prefs` снимает snapshot настроек перед попыткой, таймаут оборачивает фактический `begin_stream`, после `ExitTimeout`/`NotConnected`/`CircuitClosed` circuit retirement выполняется до единственного повтора. Повтор использует snapshot обычного `connect_timeout` (по умолчанию 10 секунд), а не новое значение после reconfigure.

Android verification теперь передаёт исходный PT path, создаёт уникальный каталог на каждый batch и check, завершает throwaway runtime до sweep, затем сопоставляет точный state-location token и использует pidfd. Это устраняет проверенные ранее collision/W^X и baseline-PID сценарии в пределах заявленной device-only проверки.

## Общий текущий код

### TS12-01 — P2: daemon writer всё ещё может перезаписать принятую CLI-мутацию устаревшим snapshot

Статус: исправлено общей блокировкой полного read-modify-write. Исправление последовательного случая TS2-01 сохраняется.

Место: `apps/socks5-proxy/src/bridge_store_writer.rs:45-69`, `:388-422`, `:568-600`; fallback CLI в `:640-649`.

Триггер: daemon уже загрузил `S`, применил mutation `A` и запустил blocking `save(S+A)`; до завершения этой записи отдельный `tor-socks5 bridges ...` процесс загружает `S`, добавляет `B` и атомарно переименовывает `S+B`.

Механизм до исправления: daemon publish использовал ранее захваченный `Arc<BridgeStore>` и без проверки версии/mtime переименовывал `S+A` поверх `S+B`. После успешного publish `absorb_publish_result` делал snapshot clean и отбрасывал его; следующая daemon-мутация перечитывала уже файл `S+A`, поэтому `B` терялась окончательно, пока CLI не повторит операцию. Уникальные temp-файлы гарантировали отсутствие torn bytes, но не сохраняли обе read-modify-write мутации.

Влияние: health counters, retirement, source attribution и свежая bridge-мутация CLI могут исчезнуть; в зависимости от момента это меняет последующий ranking/pruning и требует повторного запуска команды.

Доказательство регрессии: `bridge_store_writer_tests/cross_process_lock_tests.rs` удерживает daemon publish и запускает реальный CLI fallback в overlap; тест проверяет обе мутации. `PathLock` удерживается от clean-load до publish и сбрасывается только после clean completion.

### TS12-02 — P2: CandidatePool теряет изменения при одновременном daemon и CLI refresh/drain

Статус: исправлено общей блокировкой CandidatePool transaction.

Места: `apps/socks5-proxy/src/candidate_pool.rs:229-260`; callers `apps/socks5-proxy/src/fetch_merge.rs:136-158` и `:300-379`.

Триггер: фоновый maintenance и отдельный `tor-socks5 bridges fetch` одновременно загружают один `<stem>.candidates.log`, каждый добавляет собственный набор кандидатов, затем сохраняет snapshot.

Механизм до исправления: каждый caller делал независимый `load → merge/take → save`; `CandidatePool::save` использовал только PID в имени temp-файла и не делал lock/re-read/merge перед финальным rename. Atomic rename сохранял целостность отдельного файла, но последний writer заменял snapshot первого.

Влияние: часть свежих мостов исчезает из candidate pool и может не пройти последующую проверку/promote; при следующем refresh она обычно появится снова, поэтому это availability/data-loss P2, а не повреждение формата.

Доказательство регрессии: `candidate_pool::tests::competing_transactions_serialize_and_removals_stay_removed` и `fetch_merge::tests::drain_waits_for_a_concurrent_pool_transaction_and_both_effects_survive` принудительно перекрывают транзакции и проверяют сохранение добавления вместе с удалением.

### TS12-03 — P3: `max_body_mib` не соблюдается для body, уже прочитанного вместе с HTTP headers

Статус: исправлено проверкой buffered body до EOF-read.

Место: `packages/bridge-fetcher/src/http.rs:352-450`, особенно `:407-447`; значение без минимальной валидации задаётся `packages/proxy-config/src/lib.rs:357-361`.

Триггер: конфигурация задаёт `bridges.max_body_mib: 0`, а HTTP/1.1 ответ без `Content-Length` и без chunked encoding возвращает headers и небольшой body одним `read`, затем EOF. При прямом использовании fetcher API аналогичный случай возможен с ненулевым байтовым лимитом меньше начального буфера. Конфигурационные значения от 1 MiB этим сценарием не обходятся.

Механизм до исправления: после разбора headers код создавал `body` из `header_buf[body_start..total]`, но до цикла EOF не проверял `body.len() > max_body_bytes`. Проверка находилась только после следующего `read` (`:442-447`). Если следующий read давал EOF, уже buffered body возвращался успешно. При `max_body_bytes=0` ответ с body до размера начального 8192-byte header buffer обходил лимит; ограничение «response larger than this is rejected» нарушалось.

Влияние: источник может вернуть до примерно 8 KiB сверх настроенного лимита, что делает ограничение неточным и позволяет малой конфигурации принять неожиданный bridge-list body. Это P3: обычный default 64 MiB и Content-Length/chunked ветки не затронуты.

Детерминированные тесты `eof_body_fully_buffered_with_headers_over_limit_is_too_large`, `...exactly_at_the_limit...` и `...without_a_body...` покрывают over-limit, boundary и zero-length случаи.

## Неподтверждённые гипотезы и границы

- Android pidfd path (`packages/android-ffi/src/pt_reap.rs`) намеренно fail-closed на API ниже 31, неизвестном API, ENOSYS и denied syscall: возможна видимая утечка PT-процесса. Это заявленное ограничение recovery task, не новый P2; подтверждение device flow и seccomp policy требует устройства.
- `TOR_PT_STATE_LOCATION` composition сверена с vendored `arti-client` (`client/bootstrap.rs:481-492`) и helper-комментариями, но полная updated-APK exec/environ/pidfd последовательность на устройстве в этом раунде не выполнялась.
- `disk_fallback_store` (`packages/bridge-probe/src/dns.rs:415-417`) не имеет того же cap, что live DoH cache. Теоретически повторные Android config/QR inputs с большим числом уникальных hints могут наращивать process-global map; отдельное практическое ограничение размера входа/числа hints в контракте приложения не найдено, поэтому это не вынесено в подтверждённые P.

## Проверки

Успешно:

- `cargo test --locked -p arti-wrapper --lib -j 1 -- --quiet` — 24 passed.
- `cargo test --locked -p bridge-fetcher --lib -j 1` — 94 passed.
- `cargo test --locked -p socks5-proxy --bin socks5-proxy -j 1` — 271 passed.
- `cargo clippy --locked -p socks5-proxy -p bridge-fetcher --all-targets -j 1 -- -D warnings` — passed.

Отдельный запуск `bridge-verify-core` сначала остановился на линковке с отсутствующей системной `sqlite3.lib`. Проверка с уже используемой workspace сборкой SQLite исправила выбор feature без изменения зависимостей: `cargo test --locked -p bridge-verify-core --features rusqlite/bundled --lib -j 1 -- --quiet` — 35 passed. Ранее принятые workspace и Android ARM64 проверки относятся к отдельному этапу и здесь не повторялись.

Все три замечания проверены по исходному коду и достижимым путям вызова; для каждого добавлен и пройден regression test. Изменения не затрагивают зависимости или версии.
