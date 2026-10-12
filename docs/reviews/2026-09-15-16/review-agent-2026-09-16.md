# Ревью tor-socks5 — агентское ревью 2026-09-16

Проверенный HEAD: `0946904b4a3df8810d93f854f37798440938662f` (ветка `review-7day`).
Охваченный диапазон: `06b952c..0946904` — 43 коммита за 7 дней (`5ded6ac` TS5-02+03 … `0946904` «serialize bridge persistence updates»), серии TS5–TS12 плюс три Android-коммита от 16.09.

Это ручное ревью кода, без запуска тестов и без изменений production-кода. Каждая находка подтверждена чтением исходника (не по названию коммита/комментарию). Для каждой указано: место, механизм, условия проявления, приоритет, предложение.

## Что именно прочитано

Полностью:

- `packages/bridge-probe/src/dns.rs`, `dns_publish_pause.rs`, `probe/mod.rs`, `probe/dns_resolution.rs`, `probe/dns_invalidation.rs`, `probe/batch.rs`, `probe/webtunnel_upgrade.rs`; тесты `dns_invalidation_tests.rs`, `dns_registry_tests.rs`, список тестов `dns_save_tests.rs`.
- `packages/bridge-store/src/lib.rs`, `stats.rs`, `persistence.rs`, `observe.rs`; тесты `carrier_identity.rs`, diff `ranking.rs`.
- `packages/bridge-fetcher/src/dedup.rs`, diff `direct.rs`, `http.rs:340-465`.
- `apps/socks5-proxy/src/candidate_pool.rs`, `fetch_merge.rs`, `path_lock.rs`, `bridge_store_writer.rs`, `tor_setup.rs`, `bridge_warmer.rs`, `bridge_maintenance.rs`, `bridge_maintenance/channel_probe.rs`, `bridge_verifier.rs:1-200`.
- `packages/arti-wrapper/src/lib.rs`, `tests.rs`; `vendor/arti-client/src/client/stream_retry.rs`, diff `operations.rs`/`config.rs` (коммит `be395f9`).
- `packages/android-ffi/src/engine_bridges.rs`, `engine_bootstrap.rs` (целиком), `engine.rs:330-410`, `pt_reap.rs`, `jni_verify.rs:180-480`; `packages/bridge-verify-core/src/pt_reap.rs`.
- `packages/proxy-config/src/lib.rs:540-791`.
- docs раундов 11 и 12 — чтобы не переоткрывать уже закрытое.

## Что НЕ проверял (границы выводов)

- Vendored Arti целиком (кроме `stream_retry.rs`/`operations.rs`/`config.rs` из последнего коммита), `tor-chanmgr`, `tor-ptmgr`.
- JNI-обвязка (`jni_engine.rs` кроме `main_engine_settings`, `jni_bridges.rs`, `callback.rs`, `lib.rs` android-ffi), Kotlin-сторона, device-only пути (`/proc`, pidfd) — только чтение pure-функций и их тестов.
- SOCKS5-протокол, auth, upstream, `tor_watchdog.rs`, `server.rs`, `bridges_cmd.rs` (только точки вызова).
- Ничего не запускал: ни тесты, ни benchmarks, ни сетевые reproducer'ы. Оценки сложности — по алгоритму, не измерены.
- Гонки описаны по порядку операций в коде; временные окна оценены по константам, не по измерениям.

## Итог по приоритетам

P0: 0. P1: 0. **P2: 4. P3: 10.**

| ID | P | Область | Суть |
|---|---|---|---|
| R-01 | P2 | DNS persistence | `flush_dns_cache` + периодический save стирает из файла и из памяти все ответы текущей сессии |
| R-02 | P2 | channel_probe | `warm_bridge(..).is_ok()` принимает `Ok(false)` (чужой канал) за доказательство и пишет `channel_ok` |
| R-03 | P2 | config `.ktav` | read-modify-write конфига без lock: daemon vs CLI теряют изменения (класс TS12-01/02) |
| R-04 | P2 | arti-wrapper | `warm_bridge`/`bridge_is_disabled`/`signal_bridge_failure` игнорируют `obfs4_iat_mode` |
| R-05 | P3 | DNS invalidation | `invalidate_if_current` — no-op для hostname с ≥4 адресами (cap `MAX_PROBE_ADDRS=3`) |
| R-06 | P3 | DNS cache | negative entry без version-gate может затереть свежий ответ того же поколения |
| R-07 | P3 | INFLIGHT_DOH sweep | sweep крутит один живой ключ 128 раз, если очередь короче бюджета |
| R-08 | P3 | BridgeStore key | `bridge_identity` на каждый lookup: URL-parse + 3–5 String; sort в Android — 4 ключа на сравнение |
| R-09 | P3 | drain_pool lock | pool-lock удерживается через admission (не ограничен `deadline`) + `VERIFY_LOCK` (до ~5 мин) ≫ `POOL_LOCK_WAIT` |
| R-10 | P3 | Android store | load/save+fsync под глобальным Mutex выполняются inline на tokio worker |
| R-11 | P3 | Android warm | `warm_session_failed` не сбрасывается при смене сети (flush) |
| R-12 | P3 | stream_retry | `ExitTimeout` на быстрой 4-с попытке ретирует рабочую цепь — churn на медленных мостах |
| R-13 | P3 | durability | DNS-файл пишется без fsync; сиротские `*.pid.gen.tmp` после crash не чистятся; нет fsync каталога |
| R-14 | P3 | smell | два параллельных identity-ключа (`candidate_pool::Key` и `BridgeIdentity`); комментарии расходятся с кодом |

## P2

### R-01 — DNS: flush + save стирает ответы текущей сессии из persisted fallback

Место: `packages/bridge-probe/src/dns.rs:376-403` (`flush_dns_cache`), `:695-745` (`capture_persist_snapshots_with_generation`), `:505-515` (`merge_disk_fallback_entry` — единственные писатели `disk_fallback_store` это `load_persisted_dns_cache` и `seed_disk_fallback`); вызовы: `packages/android-ffi/src/engine_bootstrap.rs:449` (save на каждом тике watchdog, 45 с) и `:765` (flush при stall-reset), `engine.rs:365-371` (flush + load на старте).

Механизм. Live-ответы (`doh_cache`) никогда не сливаются в `disk_fallback_store`. Save пишет `live ∪ disk`. Последовательность:

1. старт: `load` → disk-store `D` (или пусто на первом запуске);
2. сессия резолвит хосты → live `L`; save #1 пишет `L ∪ D`;
3. watchdog stall (3 неудачных probe подряд) → `flush_dns_cache()` → live пуст;
4. следующий тик: save #2 пишет `∅ ∪ D` = `D`. `L` исчез из файла.

Одновременно `disk_fallback_answer` в памяти по-прежнему знает только `D`, поэтому и в этой же сессии после flush хосты из `L` не резолвятся, если DoH в новой сети заблокирован — ровно тот сценарий, ради которого fallback существует. Docstring `save_persisted_dns_cache` («a periodic save can never erase what it exists to protect») и `load_persisted_dns_cache` («can only provide one where a cold start would otherwise have none») этому противоречат.

Условия: Android, любая сессия с stall-reset (смена Wi-Fi/mobile) при пустом или устаревшем `D`. На CLI `flush_dns_cache` не вызывается — не затронут.

Тесты: `dns_save_tests.rs` (14 тестов) не содержат сценария flush→save; регрессия не поймана.

Предложение: в `flush_dns_cache` перед `cache.clear()` собрать positive+usable записи (тот же предикат `live_entry_is_usable`, `!addrs.is_empty()`) под `doh_cache`, отпустить lock, затем `merge_disk_fallback_entry` для каждой (recency-merge уже защищает от отката). Порядок локов: `doh_cache` → `disk_fallback_store` нигде не берётся в обратном порядке (`best_known_answer` и capture отпускают `doh_cache` до взятия disk-store), но безопаснее собрать и слить после drop guard. Альтернатива — делать тот же merge в `capture_persist_snapshots_with_generation`. Тест: remember → save → flush → save → load в новый процесс/чистый store → `disk_fallback_answer(host)` = Some.

### R-02 — channel_probe: `Ok(false)` от `warm_bridge` засчитывается как аутентифицированный канал

Место: `apps/socks5-proxy/src/bridge_maintenance/channel_probe.rs:110-117`:

```rust
matches!(tor.bridge_is_disabled(&bridge), Ok(false))
    && tor.warm_bridge(&bridge).await.is_ok()
    && matches!(tor.bridge_is_disabled(&bridge), Ok(false))
```

и `:138-148` — для найденных мостов пишется `note_probe_round` + `note_channel_success_at`.

Механизм. `TorTunnel::warm_bridge` (`packages/arti-wrapper/src/lib.rs:403-430`) возвращает `Ok(false)`, когда `ChanMgr::get_or_launch` выдал канал, открытый через другой carrier с теми же relay-identity (TS8-02: «callers must not record a channel-level success»). `is_ok()` на `Ok(false)` — `true`. Для obfs4 это ровно случай ротации `cert=` (TS11-02) или двух строк одного relay на разных портах: канал старого cert'а «доказывает» новую строку, она попадает в `selected.bridges` как «authenticated fallback» и получает `channel_ok_count += 1`. `fetch_merge.rs:293-296` и Android `warm_bridge_pool` (`engine_bootstrap.rs:192-205`) делают правильно — `Ok(Ok(true))`.

Условия: в конфиге ≥2 obfs4-строки одного relay (ротация cert, обновлённая строка из источника рядом со старой), preferred-transport путь с obfs4 fallback.

Тесты: `channel_probe::tests` проверяют только `ready_pool` с замыканиями; `check` не покрыт.

Предложение: `matches!(tor.warm_bridge(&bridge).await, Ok(true))`. Тест: fake `check`, возвращающий `Ok(false)` для одного из кандидатов, не должен попасть в `found`.

### R-03 — config `.ktav`: read-modify-write без блокировки (daemon ↔ CLI)

Места: `apps/socks5-proxy/src/tor_setup.rs:520-539` (`prune_bridges_from_config`: load → retain → write), `fetch_merge.rs:462-479` (promotion: load → push → write, выполняется ПОСЛЕ `drop(pool_lock)` на `:414`), `fetch_merge.rs:170-179` (migration URL: load → write). `Config::write` (`packages/proxy-config/src/lib.rs:763-787`) — atomic rename, temp-имя `.{file}.{pid}.tmp`.

Механизм. TS12-01/02 закрыли lost update для `alive-bridges.log` и `candidates.log` через `PathLock`, но сам конфиг остался без него. Daemon: `bridge_maintenance::refresh` → `refresh_routes` → `build_tor_settings_preserving_live` → `update_health_and_prune` → prune-write; CLI `tor-socks5 bridges fetch` → `drain_pool` → promotion-write. Пересечение: daemon загрузил `S`, CLI загрузил `S`, CLI записал `S+P`, daemon записал `S−D` → промоушен `P` потерян (CLI отчитался «added»), либо в обратном порядке — мёртвый `D` воскрес. Внутри одного daemon-процесса записи последовательны (одна maintenance-таска; `Recheck` не поллит `discovery` параллельно), но PID-only temp-имя означает, что любой будущий второй писатель в процессе получит ещё и общий temp-файл (тот самый дефект, что был у `CandidatePool::save`).

Условия: CLI-подкоманда во время работы daemon'а — то же условие, при котором TS12-01 признан P2.

Предложение: обернуть все три RMW в `PathLock::acquire_bounded(config_path, CLI_LOCK_WAIT)` (sibling `<config>.lock`), выполнять в `spawn_blocking`; temp-имя дополнить monotonic counter как в `BridgeStore::temp_path`. Тест по образцу `cross_process_lock_tests.rs`: parked prune vs promotion — обе мутации должны сохраниться.

### R-04 — arti-wrapper: `warm_bridge` и соседи строят target из сырой строки, минуя `obfs4_iat_mode`

Место: `packages/arti-wrapper/src/lib.rs:403-411` (`warm_bridge`), `:433-443` (`bridge_is_disabled`), `:480-489` (`signal_bridge_failure`) — `bridge.to_string().parse::<BridgeConfigBuilder>()`; тогда как `build_config` (`:739-747`) применяет `with_iat_mode_override`. Настройка: `tor_setup.rs:230` (`obfs4_iat_mode: cfg.bridges.iat_mode_override()`), `jni_engine.rs:323`.

Механизм (при `bridges.iat_mode` ≠ default, override = Some):

- канала ещё нет → `get_or_launch` запускает PT с target warmer'а, т.е. `iat-mode=0` из строки. Дальше arti переиспользует этот канал для реального трафика (ChanMgr ищет по relay-identity) → DPI-evasion режим на прогретом канале не применён;
- канал уже открыт arti'ём (с `iat-mode=1`) → `channel_proves_endpoint` сравнивает `PtTarget` полностью, включая settings → `Ok(false)` → warmer никогда не записывает `channel_ok` для obfs4 → `channel_proven_bridges`/ранжирование деградируют без видимой ошибки.

Условия: включённый override `iat_mode` (не default). При default — не проявляется.

Предложение: вынести `with_iat_mode_override` в общий helper `bridge_target(&self, line)` и использовать в трёх методах; `TorTunnel` должен помнить `obfs4_iat_mode` из своих `Settings` (поле в `TorTunnel` или передавать `&Settings`). Тест: с `obfs4_iat_mode: Some(1)` `PtTarget` из `warm_bridge` должен нести `iat-mode=1`.

## P3

### R-05 — `invalidate_if_current` не срабатывает для hostname с ≥4 адресами

Место: `packages/bridge-probe/src/probe/dns_invalidation.rs:99-103` — условие `entry.addrs.iter().all(|ip| failed_addrs.contains(ip))`; `probe/dns_resolution.rs:22` `MAX_PROBE_ADDRS = 3`; `probe/mod.rs:472-477`.

Механизм: `order_candidates` отдаёт максимум 3 адреса, `failed_addrs` ⊆ этим трём. Если в кеше ≥4 записей (типичный CDN-фронт: 2 A + 2 AAAA), `all` ложно всегда → запись никогда не инвалидируется по неудачной пробе; устаревший ответ живёт до TTL (60 с … 30 мин). До TS11-04 инвалидация была безусловной, после — фактически отключена для самых частых fronting-хостов. Тест `only_all_observed_failed_ips_invalidate_the_matching_entry` использует 2 адреса и это не ловит.

Предложение: передавать в `invalidate_if_current` набор реально опробованных адресов и требовать `tried ⊆ failed` (все опробованные отказали), а не `cached ⊆ failed`; либо инвалидировать только опробованные IP из записи. Тест с 4 адресами в кеше и 3 отказами.

### R-06 — negative entry без version-gate может затереть свежий ответ

Место: `probe/dns_resolution.rs:635-665` (fallback-цепочка → `remember_doh_failure_if_generation`), `dns.rs:273-285`, `insert_capped` → `cache.insert` безусловно.

Механизм: A получил `Err` из coalesced lookup (ячейка удалена pointwise), проверил stale/disk fallback (None), и между этими проверками и `remember_doh_failure_if_generation` B (новая ячейка, тот же generation) опубликовал свежий ответ → A перезаписывает его negative-записью на 120 с. Generation-gate не защищает (поколение одно). Окно — микросекунды, но проверка stale уже выполняется под тем же mutex, так что закрыть дёшево.

Предложение: в `remember_doh_failure_if_generation` под `doh_cache` не вставлять negative, если существующая запись positive и `expires_at > now` (или передавать `CacheIdentity` ожидаемой записи). Тест на seam `pre_publish_pause` уже есть — добавить сценарий «publish между fallback-проверкой и negative insert».

### R-07 — bounded sweep тратит весь бюджет на один живой ключ

Место: `probe/dns_resolution.rs:446-465`.

Механизм: `for _ in 0..INFLIGHT_SWEEP_BUDGET { pop_front; …; queue_key(key) }` — при `sweep_queue.len() < 128` живой ключ выталкивается и снова ставится в хвост, пока не исчерпается бюджет: 128 HashSet remove/insert + VecDeque pop/push на одну запись под глобальным mutex (тест `live_sweep_reuses_shared_hostname_allocation` это буквально фиксирует: `visited == 128` при одной записи). Корректность не страдает, работа лишняя.

Предложение: `let visits = INFLIGHT_SWEEP_BUDGET.min(registry.sweep_queue.len());`.

### R-08 — `bridge_identity` как ключ: аллокации/URL-parse на каждый lookup

Места: `packages/bridge-store/src/lib.rs:190-192` (`key_of` → `bridge_identity`), `probe/mod.rs:317-347` (`PreparedTarget::new` — `url::Url::parse` + `ServerName::try_from` + 4 String для webtunnel, плюс `transport`/`fingerprint`/`cert` clone для всех); `BTreeMap<BridgeIdentity, Entry>` — сравнение составных строк на каждом шаге поиска. Горячие потребители: `note_probe_round` (2 ключа на probed), `healthiest_among` (ключ на кандидата + `allowed.contains`), `is_retired`/`circuit_fails` в `build_tor_settings_preserving_live:68-72` и `channel_probe.rs:98-102` (2 ключа на configured), Android `persist_and_rank_probe` `engine_bridges.rs:185-191` — `sort_by` вызывает `channel_ok_count`/`ok_count` дважды на сравнение → ~4·A·log A построений identity на раунд.

Условия: пулы в тысячи мостов (по docs), каждый тик maintenance/watchdog.

Предложение: кешировать `BridgeIdentity` в `Entry` (уже есть `key()`), для сортировок — `sort_by_cached_key` по заранее снятому `(channel_ok_count, ok_count)`; рассмотреть `HashMap` вместо `BTreeMap` (порядок нужен только как tie-break — можно заменить позицией вставки) и компактный ключ (hash канонической строки) при сохранении `BridgeIdentity` для equality.

### R-09 — pool-lock удерживается дольше, чем `POOL_LOCK_WAIT` допускает

Места: `apps/socks5-proxy/src/fetch_merge.rs:343-414` (lock от load до save), `:377` (`timeout_at(deadline, probe)` — только probe), `:394` (`admits_candidate` вне `deadline`), `:280-291` (`verify_for_admission`), `bridge_verifier.rs:85-108` → `verify_bridges_sequential` → `:477` `VERIFY_LOCK` (std Mutex, до 2×(60 с bootstrap + 90 с probe) за фоновый батч), `path_lock.rs:38-42` (`POOL_LOCK_WAIT = 120 s`, комментарий «leaves headroom»).

Механизм: drain держит pool-lock через webtunnel-admission (bootstrap 60 с + probe 90 с) и через ожидание `VERIFY_LOCK` (фоновый circuit-verify держит его до ~300 с) → худший случай ~8 мин. Конкурирующий `refresh_candidate_pool`/CLI `bridges fetch` получает «busy» через 120 с, `top_up_working` пробрасывает `?` → «bridge refresh failed; keeping current routes». Не дедлок и не потеря данных (lock корректно отпускается), но документированная гарантия не выполняется, а `DRAIN_BUDGET=60 s` номинален.

Предложение: либо ограничить admission общим `deadline` (`timeout_at(deadline, admits_candidate(..))`, при истечении — `deferred`), либо не держать pool-lock через сетевые проверки: транзакция 1 — `take`/save, транзакция 2 — `return_front`/`merge`/save (removals остаются removed, т.к. taken уже удалены). Обновить комментарий к `POOL_LOCK_WAIT`.

### R-10 — Android: blocking store I/O на async worker

Места: `packages/android-ffi/src/engine_bridges.rs:155-197` (`persist_and_rank_probe`), `:257-286`, `:379-407`, `:416-451` — `BridgeStore::load` + `save` (serialize всего store + `sync_all`) под `bridge_store_write_lock()` (std Mutex); вызовы из async `stall_watchdog` (`engine_bootstrap.rs:505, 722, 781`) и `cold_start_rescue_fetch:359,375`.

Механизм: guard не пересекает `.await` (это соблюдено), но fsync и сериализация тысяч записей выполняются на tokio worker'е; CLI-сторона (`bridge_store_writer`) специально вынесла это в `spawn_blocking`. На флеше телефона fsync — десятки–сотни мс на тик, блокируя accept-loop/SOCKS-таски, разделяющие runtime.

Предложение: обернуть тело этих функций в `tokio::task::spawn_blocking` (они уже sync) — вызовы `.await` на JoinHandle; lock остаётся внутри blocking-job.

### R-11 — Android: `warm_session_failed` не сбрасывается при смене сети

Место: `engine_bootstrap.rs:421` (объявление), `:486-491` (фильтр батча), `:509-514` (пополнение), `:765` (flush при stall-reset — set не трогается).

Механизм: мост, не прогревшийся в старой сети, исключается из top-up на всю сессию; stall-reset (то, что код сам трактует как смену сети: «what a network change looks like») сбрасывает DNS/scores, но не этот набор. Rebuild-ветка прогревает `rotation_bridges`/`bridges` без фильтра, но последующие top-up раунды продолжают пропускать «старые» отказы. Рост набора ограничен размером конфига.

Предложение: `warm_session_failed.clear()` рядом с `flush_dns_cache()` на `:765`.

### R-12 — `retry_exit_stream`: таймаут быстрой первой попытки ретирует рабочую цепь

Места: `vendor/arti-client/src/client/stream_retry.rs:49-73`, `operations.rs:226-232` (`retire_circ(id)`), `jni_engine.rs` `main_engine_settings` — `initial_connect_timeout = 4 s` (только Android; CLI — None).

Механизм: `ExitTimeout` считается retryable → `retire(&id)` до повтора. На медленном мосте (webtunnel/mobile) открытие exit-stream штатно занимает 3–6 с → каждый первый CONNECT >4 с ретирует живую цепь и строит новую; повтор идёт с 10 с. Итог — регулярный churn цепей и лишние circuit builds, а не ускорение. Round 12 подтвердил корректность реализации, но не оценил этот эффект.

Предложение: при таймауте именно первой (укороченной) попытки не ретировать цепь, а только повторить на другой (или ретировать после второго таймаута); ретирование оставить для `NotConnected`/`CircuitClosed`/ordinary timeout. Тест в `client/tests.rs` на «initial timeout → no retire».

### R-13 — durability мелочи

- `dns.rs:586` — `std::fs::write` temp без `sync_all` перед `rename` (`:659`): после сбоя питания на ext4/f2fs возможен пустой/усечённый `*.dns-cache` (rename-over-existing без fsync источника). `BridgeStore::save`, `CandidatePool::save`, `Config::write` делают `sync_all` файла, но не каталога — rename может не пережить crash на Linux/Android; на Windows не актуально.
- `dns.rs:627-632` — temp-имя `{file}.{pid}.{gen}.tmp`; после crash процесса сироты никогда не удаляются (нет sweep по маске при старте). То же для `.{file}.{pid}.{seq}.tmp` store/pool/config.

Предложение: `File::create` + `write_all` + `sync_all` для DNS temp; при старте `load_*` удалять `*.tmp` своего префикса; на unix — `File::open(dir).sync_all()` после rename (best-effort).

### R-14 — code smell / расхождения комментариев с кодом

- Два определения одного ключа: `apps/socks5-proxy/src/candidate_pool.rs:59-75` (`Key` tuple) и `bridge_probe::BridgeIdentity` (`probe/mod.rs:296-325`), одинаковые поля, разные типы; `fetch_merge::working_keys` и `channel_probe::candidates` используют tuple, store/config/`tor_setup` — `BridgeIdentity`. Один источник истины: заменить tuple на `BridgeIdentity` (уже `Hash + Ord`).
- `dns.rs:542-562` docstring save — противоречит R-01. `dns.rs:517-527` docstring load — то же.
- `path_lock.rs:38-42` — «leaves headroom» неверно (R-09).
- `fetch_merge.rs:246-263` docstring drain — «cancellation drops it before any save» верно, но не сказано, что lock живёт через admission.
- `probe/mod.rs:126-133` — docstring `resolve_probe_target` склеен с docstring `PreparedTarget` (строки 126-144 описывают две сущности подряд; rustdoc отнесёт всё к `PreparedTarget`).
- `bridge-fetcher/src/dedup.rs:22-28` и `candidate_pool::key_of` дублируют `bridge_identity` вручную (третье место сборки ключа).

## Категории без подтверждённых находок

- **Дедлоки / порядок локов.** Проверены: `snapshot_lock → doh_cache | disk_fallback_store | next_generation` (leaf); `publish_lock → published_generation`; `INFLIGHT_DOH` — leaf; `flush` и `store_cached_if_generation` — только `doh_cache`; `PERSIST_PATH_STATES` — отпускается до внутренних; `PathLock` pool и store никогда не вложены (`drop(pool_lock)` на `fetch_merge.rs:414` до `bridge_store_writer::apply`); `VERIFY_LOCK` берётся только внутри `spawn_blocking`; Android `BRIDGE_STORE_WRITE_LOCK` — только в sync fn. Циклов не найдено.
- **`std::sync::Mutex` через `.await`.** Не найдено в прочитанном коде (guards в `update_health_and_prune`, `channel_probe`, `engine_bridges` — внутри sync-замыканий/функций).
- **Cancel-safety / отсоединённые задачи.** `race_first_answer`: admission-token + `DOH_PROVIDER_TIMEOUT` ограничивают detached-таски; `OnceCell::get_or_init` — waiter перенимает init при отмене owner'а; `save_persisted_dns_cache` — job самодостаточен, generation-check защищает от отката; `bridge_store_writer` publish-job — fire-and-forget с каналом результата, `close` дожидается. Замечаний нет.
- **Потеря байтов / частичная запись.** Все писатели используют temp + atomic rename; torn-файлов не найдено (кроме durability-нюансов R-13 и PID-only temp-имени `Config::write` в R-03).
- **Неограниченный рост.** `doh_cache` — cap 2048 с amortized eviction; `INFLIGHT_DOH` — bounded sweep (R-07 — только лишняя работа); `sweep_queue` — дренируется быстрее, чем растёт (128 визитов на 64 вставки); `KILL_MARKERS` — cap 128; `disk_fallback_store` — без cap, вход ограничен конфигом/QR (round 12 уже отметил, не выношу повторно); `warm_session_failed` — ограничен конфигом (R-11 — про семантику, не размер).
- **Тесты-оракулы.** Прочитанные тесты (`dns_invalidation_tests`, `dns_registry_tests`, `carrier_identity`, `ranking`, `dedup`, `candidate_pool`, `fetch_merge`, `path_lock`, `pt_reap` обоих крейтов, `arti-wrapper/tests`) проверяют реальные инварианты и содержат негативные контроли. Пробелы покрытия: flush→save (R-01), ≥4 адресов (R-05), `Ok(false)` в `channel_probe::check` (R-02), iat-override в `warm_bridge` (R-04).
- **Подтверждено как корректное** (проверено кодом, не комментарием): TS8-01 check-after-lock в `store_cached_if_generation_observed`; TS7-01/02 порядок (snapshot, generation) и публикация против `published_generation`; TS7-06 generation в ключе registry; TS10-02 bounded FIFO sweep; TS10-03/TS11-01/02/03 полный identity в dedup/pool/config/store/prune; TS12-01/02 `PathLock` вокруг полного RMW store/pool; TS12-03 pre-read cap check; TS5-02 admission-token; TS8-02 `channel_proves_endpoint` (сама функция; проблема в вызывающем — R-02); pidfd-sweep: handle до revalidate, fail-closed без numeric fallback.

## Проверки

Только чтение исходников и `git log/diff/show`. Тесты, clippy, benchmarks и сетевые reproducer'ы не запускались. Production-код и тесты не изменялись; в коммит входит только этот файл.
