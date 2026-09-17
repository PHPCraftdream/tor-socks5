# Сводное ревью tor-socks5 и ptrs-gesher — раунд 19

Дата: 2026-09-17. Отчёт объединяет ревью последних исправлений, повторную приёмку находок раунда 18 и общий проход по основным подсистемам двух репозиториев.

| Репозиторий | Проверенный HEAD | Диапазон новых правок |
|---|---|---|
| tor-socks5 | `a219463924204b851b860fc232a026f925cc1457` | `38b72bc..a219463` |
| ptrs-gesher | `9ecf4d4b5da8e606fe9c8122a6ab39481953478e` | `7e3b6b8..9ecf4d4` |

Tracked working tree обоих репозиториев на старте чистое. Посторонние untracked `docs/upstream/`, `.target-local/` и `tools/interop/test.txt` не менялись. Отчёт описывает эти срезы исходников; его собственный commit не является дополнительным проверенным изменением production.

## Краткий итог по P

Шкала: P0 — критическая общая неисправность; P1 — высокая срочность; P2 — дефект для обычного цикла исправлений; P3 — ограниченное влияние / задержки / устойчивость.

| Приоритет | tor-socks5 | ptrs-gesher | Всего |
|---|---:|---:|---:|
| P0 | 0 | 0 | 0 |
| P1 | 0 | 0 | 0 |
| P2 | 0 | 0 | 0 |
| P3 | 2 | 0 | 2 |

**Новых подтверждённых P0/P1/P2 в проверенном объёме нет. Все пять находок раунда 18 закрыты по исходным механизмам.** Два открытых P3 ниже не являются переименованием уже закрытых пунктов. Отсутствие находок не означает полного аудита всех платформ, зависимостей и криптографии.

## Открытые находки

### TS19-01 — P3: необязательная очистка при чтении теперь может ждать файловый lock без ограничения

**Срез:** новая реализация `2f9a160` и её существующие async-потребители.

**Места:** [TempLock::acquire](../packages/persist-lock/src/temp.rs#L253), [cleanup canonical temp](../packages/persist-lock/src/temp.rs#L522), [cleanup orphan companion](../packages/persist-lock/src/temp.rs#L591), [Config::from_file](../packages/proxy-config/src/lib.rs#L758), [BridgeStore::load](../packages/bridge-store/src/persistence.rs#L240). Async call sites: [maintenance](../apps/socks5-proxy/src/bridge_maintenance.rs#L165), [background verifier](../apps/socks5-proxy/src/bridge_verifier.rs#L277), [Android engine startup](../packages/android-ffi/src/engine.rs#L370).

**Механизм.** Стабильный `.templock` правильно сериализует создание и удаление имён. Однако reader-side cleanup теперь использует тот же блокирующий `File::lock()` без deadline, что writer. Обычное чтение Config/BridgeStore запускает cleanup синхронно. Перечисленные async-функции вызывают чтение непосредственно на Tokio worker.

**Условия.** В каталоге найден canonical temp или orphan companion; другой процесс находится внутри name-state transition и задержан планировщиком, остановлен либо ждёт медленную файловую операцию. Cleanup не может просто пропустить занятую запись: он ждёт освобождения стабильного lock. Rust runtime не может отменить выполняющийся синхронный `File::lock` через async timeout.

**Влияние.** Ненужная задержка read-only операции и блокировка worker, потенциально вместе с SOCKS/recovery задачами на нём. Обычная короткая транзакция проходит быстро; постоянный deadlock или потеря данных здесь не утверждаются. Именно поэтому P3.

**Подтверждение.** Во временной копии текущего `temp.rs` добавлен только сигнал перед `file.lock()`. При удерживаемом `.templock` cleanup достиг этого места и не завершился; после unlock завершился. Использованы небольшой temp-файл и синхронизация потоков, без нагрузки и без изменения репозитория. Эффект на Tokio следует из синхронного пути вызовов; полноценный тест с heartbeat runtime не запускался.

**Исправление.** Для best-effort reader cleanup использовать неблокирующий захват стабильного lock и пропуск при занятости. Writer и критические удаления должны сохранить стабильную синхронизацию, закрывающую TS18-01. Отдельно переносить обязательные файловые операции async-потребителей на blocking pool. Regression: читатель возвращает данные при занятом `.templock`, живой temp остаётся нетронутым.

### TS19-02 — P3: готовые IP pins не ускоряют холодный fetch при медленном DNS

**Срез:** общий код вне последних исправлений.

**Места:** [описание pins](../packages/bridge-fetcher/src/direct.rs#L20), [connect_direct](../packages/bridge-fetcher/src/direct.rs#L63), [ожидание resolver](../packages/bridge-fetcher/src/direct.rs#L78), [первый TCP dial](../packages/bridge-fetcher/src/direct.rs#L97), [общий timeout fetch](../packages/bridge-fetcher/src/http.rs), [две DoH-волны по четыре секунды](../packages/bridge-probe/src/dns.rs#L107).

**Механизм.** `pinned_addrs` заполняет список сразу, но до попытки подключения код безусловно ожидает `resolve_addrs` для hostname. До цикла `TcpStream::connect` выполнение доходит только после результата DNS. Это отличается от описанного shortcuts-first поведения: pins первые лишь в готовом списке, а не по времени начала подключения.

**Условия и влияние.** На первом холодном запросе к известному source host, при отсутствии пригодного cache и недоступном DoH, две волны могут занять около восьми секунд даже при рабочем pin. Если caller дал fetch меньший общий budget, timeout наступит до первой попытки соединения с готовым IP. При обычном большем budget это лишняя задержка восстановления связи. Очередь provider jobs может дополнительно увеличить ожидание; точная скорость в реальной сети не измерялась.

**Подтверждение:** control flow `pinned_addrs → resolve_addrs.await → TCP loop`. Внешние DNS/bridge запросы для воспроизведения не запускались. Это не утверждение, что pins всегда актуальны, и не рекомендация доверять им без TLS.

**Исправление.** Попытаться соединиться с pins до DNS либо вести их dial параллельно с ограниченным resolver; после неуспеха использовать динамические адреса. Сохранить общий budget и проверку TLS certificate/SNI. Regression: fake resolver остаётся pending, pin-dial успешен; fetch должен перейти к TLS, не дожидаясь DNS.

## Приёмка пяти замечаний раунда 18

| ID | Статус | Доказательство в текущем коде |
|---|---|---|
| TS18-01 | Закрыт | Постоянный `<target>.templock` охватывает создание ownership, решения cleanup и unlink; под lock повторно проверяется orphanhood. Сам templock не удаляется. Новое замечание о блокировке читателя отдельно обозначено TS19-01 |
| TS18-02 | Закрыт | Early return при `promoted.is_empty()` удалён; confirm выполняет удаление dead и при нулевой promotion |
| TS18-03 | Закрыт | Attempted-deferred собираются и `rotate_to_back` вызывается на свежезагруженном pool внутри confirm; отсутствующие записи не воскрешаются |
| PT18-01 | Закрыт | Reader и writer теперь наблюдаются через `try_join!` в тесте, сравнивается содержимое, ранний EOF даёт ошибку; echo handle дожидаются на обычном пути |
| PT18-02 | Закрыт | `AtomicWriteError` различает pre/post-publication failure; `PublishedButNotDurable` сохраняет опубликованные bytes в observation того же builder и оставляет persistence pending |

Подробные исходные находки: [tor-socks5, раунд 18](review-round-18-2026-09-17.md), [ptrs-gesher, раунд 18](../../ptrs-gesher/docs/review-round-18-2026-09-17.md).

Дополнительные проверки приёмки:

- `rotate_to_back` сохраняет membership и порядок оставшегося пула; подтверждение не переписывает snapshot, прочитанный до конкурентного refresh.
- При ошибке config promotion успешные кандидаты остаются в pool; удаление dead и вращение deferred выполняются независимо от успеха config.
- `AtomicWriteError::NotPublished` не меняет observation; post-publication ветка сохраняет уже вычисленные identity/DRBG/overrides, а не генерирует их повторно.
- Замена двух DNS test-lock на один закрывает взаимное нарушение изоляции между cache и registry тестами. Новый oneshot позволяет сообщить потерю entry вместо ожидания fake lookup, для которого никто не отправит release.
- Mutation-coverage комментарий в persist-lock tests честно различает платформы; зелёный тест на Windows не приравнивается к доказательству всех Unix interleavings.

## Общий проход по репозиториям

**tor-socks5:** persistence ownership/cleanup/publish; DNS coalescing/cache/fallback/generation; pool selection/promotion/requeue; worker ownership admission; auth hashing/TOFU/registry transactions; SOCKS handshake и admission permits; async maintenance и Android startup; прямой fetch и его timeout; wrapper/retry и граница доставки PT. Более ранние неизменённые пути сверены с предыдущими отчётами. Помимо двух P3 выше новых подтверждённых находок в прочитанном коде нет.

**ptrs-gesher:** state builder/cache и post-publish recovery; echo-тесты; obfs4 stream/framing и length-distribution; core env/args; managed SOCKS client и connection lifecycle; WebTunnel handshake/DNS и границы режимов. В новых правках и в проверенных общих путях дополнительных P-находок не подтверждено.

Сохраняются явные ограничения, не посчитанные новыми дефектами:

- Старые бинарники не участвуют в новом companion/templock протоколе; mixed-version cleanup не получает автоматически его гарантий.
- Отмена всего drain отличается от истечения admission decision: произвольный abort может оставить worker выполняться до собственного завершения.
- Отдельные filesystem syscalls не становятся жёстко ограниченными по времени от проверки deadline между ними.
- `experimental-server` в lyrebird остаётся явно незавершённым и выключенным по умолчанию.
- tor-socks5 зависит от registry PT 0.5.3; соседний исправленный ptrs-gesher checkout не подключается к его сборке автоматически.
- Windows directory durability отличается от Unix; device/power-loss проверка не выполнялась.

## Выполненные проверки

Все cargo-команды запускались с `CARGO_PROFILE_TEST_DEBUG=0`, `--locked`, `-j 1`.

| Репозиторий | Команда после `cargo test --locked` | Результат |
|---|---|---|
| tor-socks5 | `-p persist-lock -j 1` | 20 unit + 3 integration passed |
| tor-socks5 | `-p socks5-proxy --bin socks5-proxy fetch_merge::tests -j 1` | 18 passed |
| tor-socks5 | `-p bridge-probe --lib -j 1` | 133 passed |
| ptrs-gesher | `-p ptrs-gesher-obfs4 --lib -j 1` | 226 passed |

Всего **400 успешных тестов** в этих запусках. ERROR-логи отрицательных framing/proptest cases не были падениями тестов. Дополнительно выполнен небольшой harness reader cleanup под удерживаемым templock и чтение diff/call sites. Зелёный тестовый результат не использован как единственное доказательство корректности.

Это ограниченное ручное ревью по направлениям rust-intel, без субагентов. Не выполнены полный workspace test/clippy в этом проходе, CVE/semver-аудит, Miri, полный криптографический аудит, все vendored Arti/Kotlin файлы, внешние мосты и Android device tests. Охват не заявляется как исчерпывающая проверка каждого файла.

## Выполнение запроса

| Этап | Статус |
|---|---|
| Определить текущие срезы обоих репозиториев | Завершён |
| Проверить новые исправления и пять прежних находок | Завершён |
| Общий проход по основным подсистемам | Завершён в указанном объёме |
| Проверки и сводка по P0–P3 | Завершены |

Для запроса подготовлен один сводный файл в tor-socks5. В commit отчёта включается только этот файл. Production-код, зависимости и версии не менялись; push не выполняется.
