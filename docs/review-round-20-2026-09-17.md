# Сводное ревью tor-socks5 и ptrs-gesher — раунд 20

Дата: 2026-09-17. Проверены последние изменения после раунда 19 и основные связанные подсистемы обоих репозиториев. Это ревью кода, а не выполнение исправлений.

| Репозиторий | Проверенный HEAD | Изменения после прошлого прохода |
|---|---|---|
| tor-socks5 | `70f76d75bf454f3e96776a62101dc4a85095341d` | `ea3f2e1..70f76d7`: pins-first fetch; неблокирующий reader cleanup; off-worker load; перенос DNS hints; тесты |
| ptrs-gesher | `9ecf4d4b5da8e606fe9c8122a6ab39481953478e` | Новых коммитов относительно раунда 19 нет |

Tracked working tree обоих репозиториев на старте чистое. Посторонние untracked `docs/upstream/`, `.target-local/` и `tools/interop/test.txt` не менялись. Commit этого отчёта не входит в проверенный production-срез.

## Итог по P

P0 — критическая общая неисправность; P1 — высокая срочность; P2 — дефект обычного цикла исправлений; P3 — ограниченное влияние / качество документации.

| Приоритет | tor-socks5 | ptrs-gesher | Всего |
|---|---:|---:|---:|
| P0 | 0 | 0 | 0 |
| P1 | 0 | 0 | 0 |
| P2 | 1 | 0 | 1 |
| P3 | 1 | 0 | 1 |

Оба пункта ниже открыты. Новых подтверждённых P0/P1 нет. Исходные TS19-01/02 закрыты по своим механизмам. Отсутствие находок в ptrs-gesher относится к указанному ограниченному повторному проходу, а не к полному аудиту репозитория.

## Находки

### TS20-01 — P2: успешный TCP dial к неработающему HTTPS pin блокирует остальные адреса

**Срез:** общий путь direct HTTPS fetch; дефект существовал до `5377002` и сохранился в изменённом connector. Не является регрессией самого переноса DNS после pins.

**Места:** [ранний возврат pin stream](../packages/bridge-fetcher/src/direct.rs#L116), [вызов connector и единственная TLS-попытка](../packages/bridge-fetcher/src/http.rs#L297), [fetch_one_direct с общим timeout](../packages/bridge-fetcher/src/http.rs#L218).

**Механизм.** `connect_dialing_pins` считает кандидата выбранным сразу после успешного `TcpStream::connect`. Контроль над перебором адресов на этом заканчивается. TLS handshake выполняется выше, в `fetch_one_inner`; его ошибка возвращается через `?` из fetch, а не обратно в цикл адресов. Оставшиеся pins и динамические адреса не проверяются. При зависании TLS их также не успевают попробовать: истекает общий timeout.

**Условия проявления.** Первый pin ещё принимает TCP на 443, но больше не обслуживает нужный hostname, сбрасывает TLS или зависает на handshake. При этом другой pin либо свежий DNS-адрес исправен. Изменение адреса backend, частичная сетевая фильтрация или устаревший pin могут дать такой результат. В ревью не утверждается, что текущие публичные pins действительно устарели: проверен путь обработки этого состояния.

**Последствие.** Cold-start rescue fetch не получает список мостов от доступного через другой адрес источника. Повтор того же fetch снова выбирает первый TCP-доступный pin; health state, исключающего его после TLS-отказа, здесь нет. Источник может перестать помогать восстановлению связи, хотя обход через динамические адреса возможен.

**Граница безопасности.** TLS certificate/SNI validation остаётся включённой. Находка об отказоустойчивости, не о принятии чужого сертификата или утечке credentials. Успешный pins-first TCP-тест не доказывает успешный HTTPS fetch.

**Доказательство.** Трассировка `connect_direct → connect_dialing_pins → return stream → TlsConnector::connect → ?`. Сверен старый код `ea3f2e1`: там тоже возвращался первый TCP-доступный stream, поэтому происхождение помечено как общий код. Новые тесты покрывают pending DNS и TCP-refused pin, но не TCP-success + TLS-failure. Сетевой reproducer с публичными источниками не запускался.

**Исправление.** Сохранить pins-first latency, но переносить выбор окончательного кандидата на уровень успешно установленного TLS для исходного hostname. После transport/TLS-отказа до отправки запроса пробовать следующий адрес, затем DNS, внутри общего budget. Не отключать валидацию и не переходить на plaintext. Regression: первый локальный pin принимает TCP и отвергает TLS; следующий кандидат даёт валидный TLS/HTTP ответ — fetch должен завершиться успешно. Отдельно проверить зависший первый TLS handshake.

### TS20-02 — P3: перенос dns_hint.rs оставил четыре неразрешимые rustdoc-ссылки

**Срез:** текущая правка `70f76d7`.

**Места:** [CachedAnswer](../packages/bridge-probe/src/dns_hint.rs#L23), [DNS_TIMESTAMP_FUTURE_TOLERANCE](../packages/bridge-probe/src/dns_hint.rs#L61), [resolve_addrs](../packages/bridge-probe/src/dns_hint.rs#L104), [load_persisted_dns_cache](../packages/bridge-probe/src/dns_hint.rs#L139).

**Механизм.** Doc comments перенесены из `dns.rs` вместе с API, но короткие имена ссылок больше не находятся в scope нового модуля. Re-export из crate root сохраняет Rust API потребителей, но не восстанавливает разрешение этих ссылок внутри `dns_hint`.

**Доказательство выполнением:**

```text
cargo doc --locked -p bridge-probe --no-deps -j 1
warning: unresolved link to CachedAnswer
warning: unresolved link to DNS_TIMESTAMP_FUTURE_TOLERANCE
warning: unresolved link to resolve_addrs
warning: unresolved link to load_persisted_dns_cache
```

Команда завершилась успешно с предупреждениями. Всего rustdoc сообщил 10 warnings: четыре unresolved links выше и шесть ссылок публичной документации на private items. Последние не объявлены шестью новыми регрессиями — часть унаследована из старой документации.

**Последствие.** Сгенерированная документация API содержит сломанные переходы; сборка с запретом `rustdoc::broken_intra_doc_links` будет отклонена. На работу DNS в runtime это не влияет.

**Исправление.** Для публичных API использовать квалифицированные `crate::...` ссылки; названия private implementation details оформить обычным code text либо убрать из публичного контракта. Проверить обычную публичную документацию без `--document-private-items`.

## Приёмка замечаний раунда 19

| Пункт | Статус | Проверка |
|---|---|---|
| TS19-01: reader cleanup ждёт templock | Закрыт | Оба reader cleanup пути используют `TempLock::try_acquire`; занятый lock приводит к пропуску. Writer create/drop сохраняют обязательную синхронизацию |
| TS19-01: выбранные async-load пути | Основные названные пути перенесены | Первый maintenance config load, background circuit-verifier store load и Android DNS startup load выполняют I/O через blocking pool; thread-id тесты прошли |
| TS19-02: DNS ожидается до первого pin dial | Закрыт | Pins действительно dial-ятся до вызова resolver; при рабочем pin resolver не нужен; после отказа всех TCP pins вызывается resolver |

Не расширяем приёмку до несуществующей гарантии «в проекте больше нет синхронного I/O на worker»: например, повторный config read после успешного discovery остаётся прямым вызовом в `bridge_maintenance.rs`. Новая неблокирующая lock-политика действует и на него, но отдельные файловые операции по-прежнему синхронны. Это граница охвата исправления, не повторное открытие закрытого ожидания lock.

Ранее закрытые TS18/PT18 при этом не переоткрываются. Постоянный templock не удаляется; writer/cleanup name transitions согласованы; drain подтверждает dead-only результат и вращает deferred; echo-оракул наблюдается; post-publish fsync error сохраняет observation builder.

## Общий проход и границы

**tor-socks5:** повторно проверены persistence protocol, reader cleanup, config/store/DNS call sites, структура DNS hints и сохранение re-export API, прямой fetch через TCP/TLS/HTTP, timeout и переходы между адресами. Сверены связанные admission/promotion/bridge-health пути и прежние закрытые механизмы. API и архитектура SDK не переделывались в рамках этого ревью.

**ptrs-gesher:** HEAD не изменился. Повторно просмотрены post-publish builder recovery, WebTunnel DNS fallback и TLS boundary, передача ошибок listener после cleanup и ранее исправленный echo lifecycle. Известные ограничения экспериментального server режима и Windows directory durability не выданы за новые находки. Новых подтверждённых дефектов в этом проходе нет; прошлые тестовые результаты не представлены как новые запуски.

Использован ограниченный ручной проход по направлениям rust-intel: ownership, cancellation, error paths, межпроцессное состояние и доказательность тестов. Субагенты не запускались. Полное прочтение всех исходников, аудит криптопримитивов, CVE/semver, Miri, Android device/power-loss и сетевой interop не выполнялись. Неизменённые подсистемы частично опираются на предыдущие проходы; этот отчёт не обещает исчерпывающего покрытия.

## Проверки этого прохода

Cargo test запускались с `CARGO_PROFILE_TEST_DEBUG=0`, `--locked`, `-j 1`.

| Проверка | Результат |
|---|---|
| `cargo test --locked -p persist-lock -j 1` | 22 unit + 3 integration passed |
| `cargo test --locked -p bridge-fetcher --lib direct::tests -j 1` | 8 passed |
| `cargo test --locked -p bridge-probe --lib -j 1` | 134 passed |
| `cargo test --locked -p socks5-proxy --bin socks5-proxy ts19_tests -j 1` | 2 passed |
| `cargo doc --locked -p bridge-probe --no-deps -j 1` | Exit 0; 10 warnings, классифицированы в TS20-02 |

Итого **169 успешных тестов**, падений не было. Полные workspace tests/clippy повторно не запускались. TS20-01 подтверждён control flow, TS20-02 — rustdoc diagnostics. Production-код для воспроизведения не менялся; внешние bridge/DNS endpoints и искусственная нагрузка не использовались.

## Выполнение запроса

Инвентаризация срезов, ревью правок, ограниченный общий проход и сведение по P завершены. Подготовлен один файл с обоими репозиториями; в commit включается только этот отчёт. Исходники, версии и зависимости не изменялись; push не выполняется.
