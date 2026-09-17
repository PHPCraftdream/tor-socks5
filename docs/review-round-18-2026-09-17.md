# tor-socks5: повторное ревью исправлений и общего кода

Дата: 2026-09-17. Финальный проверенный HEAD: `38b72bcfc95e8ebc0c5f92bc527fc764d133ebdd`. На старте был `41165b5` с чистым tracked working tree; появившийся во время ревью commit `38b72bc` дополнительно проверен. `docs/upstream/` не менялся. Базовый прошлый отчёт: [ревью TS17](review-2026-09-17.md). Прочитан диапазон `b5777b1..38b72bc`, особо подробно — исправления TS17 после `f9e1eb7`. Названия коммитов не использовались как доказательство закрытия.

Шкала: P0 — критическая общая неисправность; P1 — высокая срочность; P2 — исправить в обычном цикле разработки; P3 — ограниченное влияние / устойчивость / стоимость. **Подтверждено: P0 — 0, P1 — 0, P2 — 3, P3 — 0.** Все новые находки открыты; это вывод в границах описанного ниже прохода.

## Находки по приоритетам

| ID | P | Срез | Место | Проблема |
|---|---|---|---|---|
| TS18-01 | P2 | Новая persistence реализация | `packages/persist-lock/src/temp.rs:318–327` | Cleanup удаляет companion после передачи его lock живому writer |
| TS18-02 | P2 | Новая drain транзакция | `apps/socks5-proxy/src/fetch_merge.rs:475–477` | Раунд без promotion не подтверждает удаление мёртвых кандидатов |
| TS18-03 | P2 | Новая drain транзакция | `apps/socks5-proxy/src/fetch_merge.rs:396–398,422–446` | Отложенная первая пачка навсегда вытесняет следующие кандидаты |

### TS18-01 — P2: companion-lock можно удалить у живого владельца

Связанные места: [создание companion](../packages/persist-lock/src/temp.rs#L146), [очистка orphan companion](../packages/persist-lock/src/temp.rs#L318), [remove_temp_if_unlocked](../packages/persist-lock/src/temp.rs#L260).

**Механизм.** Writer сначала создаёт/открывает companion и лишь затем вызывает `try_lock`. Cleanup считает companion без temp сиротой, берёт его lock, **закрывает handle**, затем удаляет имя. Между закрытием и удалением writer может получить lock на тот же файл и создать temp. Cleanup удаляет companion уже после этого. Следующий cleanup не видит companion и считает temp безусловно неиспользуемым.

**Детерминированное чередование:**

1. A выполняет `open(companion)` в `TempFileGuard::create`, остановлен перед `try_lock`; temp ещё нет.
2. B проходит `!temp.exists()`, успешно берёт lock, делает `drop(handle)` и останавливается перед `remove_file(lock)`.
3. A берёт lock и создаёт temp, возвращает живой guard.
4. B удаляет companion. A всё ещё владеет handle, но имя уже отсутствует.
5. Следующий cleanup удаляет temp A через ветку `NotFound` companion. `finish()` A не может сделать rename.

**Доказательство выполнением.** Во временном каталоге скомпилирована копия текущего `temp.rs`, добавлены только barrier-seams в двух названных окнах. Логика production-функций не заменялась. На Windows получено:

```text
live_temp_exists_before_second_cleanup=true
live_companion_removed=true
live_temp_deleted=true
publish_failed=true
```

Основной checkout не менялся. Это небольшой локальный interleaving-reproducer, не нагрузочный тест. Он воспроизводит проблему при первом создании нового имени; PID reuse не требуется. Аналогичный `drop(lock)` перед unlink есть в `remove_temp_if_unlocked`.

**Влияние.** Отказ сохранений DNS/config/bridge-store/users после появления живого guard. Первоначальное удаление по чужому PID исправлено, но полная защита активного writer всё ещё не обеспечена. Текущие тесты начинают cleanup после полного создания guard; окно до захвата ownership-lock они не покрывают.

**Исправление.** Сериализовать создание/удаление companion и публикацию temp стабильным lock, который не unlink-ится, либо другим протоколом без замены lock-объекта под уже открытым handle. Простого переноса unlink перед `drop(handle)` недостаточно: нужно учитывать writer, уже открывший старый companion. Добавить forcing-тест на окно `open → try_lock`, а не только на полностью созданный guard.

### TS18-02 — P2: early return сохраняет явно мёртвую пачку навсегда

Места: [накопление dead](../apps/socks5-proxy/src/fetch_merge.rs#L449), [early return](../apps/socks5-proxy/src/fetch_merge.rs#L475), [недостижимый для этого случая confirm](../apps/socks5-proxy/src/fetch_merge.rs#L547).

**Механизм.** После проверки pool snapshot больше не сохраняется. Удаления публикует поздний confirm. Но `if promoted.is_empty() { return Ok(0); }` остался перед ним. Поэтому `dead` не применяется, когда ни один мост не прошёл admission.

**Контрпример.** Pool содержит 12 TCP-unreachable мостов и рабочий мост на позиции 13 того же транспорта. Каждый drain выбирает первые 12 (`MAX_DRAIN_ATTEMPTS`), накапливает `dead`, возвращает 0 и оставляет файл без изменений. Перемешивание происходит после отбора и не открывает доступ к позиции 13. Следующие раунды повторяют ту же мёртвую пачку.

**Влияние.** Discovery не продвигается к рабочим мостам. Это регрессия `263fe16`: обещание «dead always discarded» нарушено прямо в control flow. Тест `tcp_dead_rejects_without_consulting_channel_check` проверяет только admission, а не сохранение результатов целого drain.

**Исправление.** Проводить confirm мёртвых кандидатов и при нулевой promotion. Имеющийся ниже `promotion = if promoted.is_empty() { Ok(0) } ...` уже описывает нужный случай, но сейчас он недостижим. Regression: полностью мёртвый первый batch, затем следующий drain должен проверить кандидата за его пределами.

### TS18-03 — P2: deferred-кандидаты больше не переходят в конец очереди

Места: [ограниченный отбор](../apps/socks5-proxy/src/fetch_merge.rs#L396), [unmeasured/timeout](../apps/socks5-proxy/src/fetch_merge.rs#L421), [неуспешный admission](../apps/socks5-proxy/src/fetch_merge.rs#L445), [take_transport](../apps/socks5-proxy/src/candidate_pool.rs#L178).

**Механизм.** Новая схема оставляет deferred и unmeasured в прежних позициях on-disk pool. Следующий drain снова берёт тот же prefix. В предыдущей схеме их собирали отдельно и возвращали через `pool.merge(deferred, ...)` после оставшихся кандидатов. `shuffle` меняет порядок только уже взятой пачки.

**Контрпример.** Первые 12 WebTunnel endpoints отвечают TCP/HTTP, но не проходят полноценную Tor-проверку; за ними расположен исправный endpoint. Отказы являются deferred, а не dead. Даже после исправления TS18-02 эти 12 не будут удалены и останутся перед рабочим мостом во всех следующих раундах. Аналогично работает первая пачка с постоянным DNS Unmeasured.

**Влияние.** Рабочие кандидаты голодают; повторный fetch с dedup сам по себе не продвигает существующий prefix. Это отдельная причина остановки очереди: удаление dead не исправляет deferred.

**Исправление.** Сохранить безопасную для config-failure транзакционную схему и восстановить продвижение очереди: вращать attempted-deferred после свежего reload либо вести корректный cursor. Не перезаписывать pool старым snapshot. Regression: больше 12 кандидатов одного транспорта, первая пачка deferred, рабочий хвост обязан быть достигнут за конечное число раундов.

## Приёмка предыдущих замечаний

| Старый ID | Результат повторного чтения |
|---|---|
| TS17-01 | Частично: PID-эвристика удалена; companion создаёт новую доказанную гонку TS18-01 |
| TS17-02 | Timeout-путь закрыт: worker зарегистрирован до await, решение идёт через oneshot, drain делает join после pool-lock; snapshot принимает deadline |
| TS17-03 | Закрыт: flush и capture используют общий transition gate в согласованном порядке |
| TS17-04 | Несовпадение новых имён закрыто общим генератором и parser; legacy sweep выделен отдельно |
| TS17-05 | Закрыт: `parent_dir` нормализует пустого родителя в `.` |
| TS17-06 | Закрыт: single-slot cache удалён; Android вызывает `rank_probe_round` с `sort_by_cached_key` и одним lookup на bridge |
| TS17-07 | Закрыт для участвующих daemon/CLI writer: общий PathLock охватывает load → mutate → save; интерактивный prompt и hashing вынесены до lock |
| TS17-08 | Потеря кандидата при ошибке config закрыта сохранением его в pool до promotion; новые проблемы продвижения описаны TS18-02/03 |

«Закрыт» здесь относится к исходному механизму, не к доказательству корректности всей подсистемы. Forced abort всего drain всё ещё может отсоединить blocking jobs; это прямо отмечено в `AdmissionWorkers`, не выдано за исправленное произвольное cancellation. Отдельная файловая операция может задержаться дольше cooperative deadline — `join_all` не является жёстким wall-clock пределом для неисправного диска.

Legacy temp старого бинарника может не иметь нового companion. Отсутствие companion в смешанном запуске старой и новой версий не доказывает смерть writer; новую гарантию нельзя распространять на старые исполняемые файлы. Это граница миграции, дополнительно к воспроизведённой гонке двух новых участников.

## Проверки и общий охват

Выполнены:

- `CARGO_PROFILE_TEST_DEBUG=0 cargo test --locked -p persist-lock -j 1`: 16 unit + 3 integration — прошли.
- `CARGO_PROFILE_TEST_DEBUG=0 cargo test --locked -p socks5-proxy --bin socks5-proxy fetch_merge::tests -j 1`: 15 passed.
- После появления `38b72bc`: `CARGO_PROFILE_TEST_DEBUG=0 cargo test --locked -p bridge-probe --lib -j 1`: 133 passed. Замена глобальных registry-length assertions на per-host проверку сохраняет проверяемое свойство удаления/удержания конкретного lookup; расширенный guard не считается доказательством отсутствия всех возможных флейков.
- Отдельный barrier-reproducer TS18-01 из текущего helper: живой temp удалён, publish завершился ошибкой, как предсказывает сценарий.

TS18-02/03 подтверждены чтением целого drain и pool-selection пути; новых интеграционных тестов на эти сценарии не добавляли. Зелёный существующий набор не покрывает dead-only confirm и движение очереди при deferred prefix.

Общий проход, кроме diff: auth/SOCKS handshake и границы blocking verification, bridge maintenance/discovery/recovery, HTTP redirect credentials и ограничение fetch, DNS live/fallback/publish, Android ranking/persistence, shared snapshot и save lifecycle. Часть неизменённых подсистем сверена с предыдущим подробным ревью. Полный аудит всех vendored Arti, Kotlin, криптографии, CVE и платформ не заявляется. Новых подтверждённых P-находок вне описанных путей в этом проходе нет.

`rust-intel` использован как рамка проверки ownership/cancel-safety, межпроцессного состояния и тестовых оракулов. Работа выполнена без субагентов; пользовательский запрет на их самостоятельный запуск имеет приоритет над рекомендациями локальных инструкций. Нагрузка, внешний Tor-трафик и power-loss тесты не запускались. Production-файлы, зависимости и версии не менялись; commit/push не выполнялись. Зависимости PT в tor-socks5 по-прежнему registry 0.5.3, а не соседний checkout.
