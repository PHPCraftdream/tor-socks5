# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Stale-channel watchdog**: `arti-client` 0.43 has no hook on network-
  change events and `TorClient::reconfigure()` does not reset already-open
  channels, so a Tor client left running across a Wi-Fi/network switch can
  keep retrying circuits over half-open channels indefinitely — the
  default Windows TCP keepalive is measured in hours, so the OS-level
  dead-channel signal arti relies on may never arrive. A new background
  task (`tor_watchdog.rs`) detects "no successful circuit in the stale
  window despite attempts and TCP-alive bridges" and rebuilds the
  `TorClient` in place, swapping it in for new connections via a
  `TorHandle` indirection — no process restart required. Configurable via
  a new `[watchdog]` config section (`enabled`, `check_interval_secs`,
  `stale_after_secs`, `rebuild_cooldown_secs`); disabled bridges/health
  detection is unaffected.
- Explicit `info!`-level log line ("tor connection established") on a
  successful Tor `connect`, alongside the existing per-attempt and
  per-error logging — makes it possible to tell "working" from "hung" by
  grepping logs, rather than inferring it from the absence of errors.

### Fixed

- The stale-channel watchdog's rebuild had no timeout: on a fully-blocked
  network the fresh bootstrap could hang indefinitely while the old
  (also-failing) `TorClient` stayed alive, resulting in two concurrent
  `TorClient`s and two child `lyrebird` PT processes competing for the
  same tokio runtime and busybox PT — observed live as three
  `tor-socks5.exe` processes instead of two, worsening an already-bad
  connectivity window instead of helping. The rebuild is now bounded by a
  90s timeout, and after 3 consecutive failed rebuilds (timeout or error)
  the cooldown extends to 30 minutes so a persistently blocked network is
  not hammered every few minutes.
- Windows console output: ANSI/VT100 escape sequences from the logging
  stack now render as color instead of raw `\x1b[...m` bytes. Classic
  `conhost` (unlike Windows Terminal) does not opt in to
  `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on its own; the process now enables
  it explicitly at startup via `SetConsoleMode`, which also fixes the
  pluggable-transport child's (lyrebird's) colored output since it
  inherits the same console.
- Telegram-style connection bursts (dozens of simultaneous SOCKS5
  connects) could drive every configured guard to "unsuitable to purpose"
  under a small Tokio worker pool, reproducing the original bootstrap-time
  starvation bug at sustained scale. `worker_threads` raised 16 → 32 for
  both the main proxy runtime and the pluggable-transport child runtime;
  confirmed via A/B burst-testing (61 guard-exhaustion occurrences at 16
  workers vs. 0 at 32, identical bridge pool).
- The watchdog's rebuild always targeted the same fixed sibling state
  directory (`arti-data/watchdog-rebuild`). This worked for exactly one
  rebuild — after the first success moved the live client into that
  directory, every subsequent rebuild collided with its exclusive lock and
  failed fast (~5s) instead of actually retrying, observed live as 9
  consecutive `rebuild failed` events with a climbing
  `consecutive_failures` count. Fixed by alternating between two sibling
  directories (`watchdog-rebuild-a`/`-b`), always targeting whichever one
  is not currently live.
- The rebuild's 90s timeout wrapped the entire bootstrap call
  (`TorClient::create_bootstrapped`), a single `async` function that
  synchronously spawns several detached background tasks (channel/circuit/
  directory/PT managers) before it can return a value. Cancelling that
  future on timeout dropped the only reference to the half-constructed
  client, but the detached tasks — and any already-spawned PT child
  process — kept running ownerless for the life of the process, observed
  live as extra near-zero-memory `tor-socks5.exe` processes accumulating
  after repeated watchdog timeouts. Fixed by switching to the two-phase
  bootstrap API `arti-client` already exposes
  (`create_unbootstrapped()` — synchronous, cannot be cancelled mid-way —
  followed by a separately-timed `.bootstrap()`): a timeout now only
  abandons the network-wait, never ownership, so a timed-out client is
  explicitly and safely dropped instead of leaked.
- Even with the two-phase bootstrap fix above, dropping a `TorClient` still
  left its pluggable-transport child process running forever: arti sets
  `TOR_PT_EXIT_ON_STDIN_CLOSE=1` and closes the child's stdin as its
  shutdown signal, but our PT child (`ptrs-gesher-lyrebird` 0.5.1, run via
  busybox dispatch of our own binary) never reads stdin at all — the
  detection helper exists in `ptrs-gesher-core` but nothing calls it,
  unlike upstream Go lyrebird. Every watchdog-triggered rebuild therefore
  leaked one more permanent zombie process; 16 were found accumulated on
  one production deployment. Fixed with a small dedicated OS thread in the
  PT-child branch that blocks on `stdin` and calls `process::exit(0)` on
  EOF, restoring the contract our own binary is supposed to honor as a PT
  child regardless of what the pluggable-transport crate does.
- The two-slot `watchdog-rebuild-a`/`-b` ping-pong (see above) assumed the
  slot that is not currently live is always free to reuse. It is not:
  `TorHandle::swap` only drops its own reference to the outgoing
  `TorTunnel`, while the underlying `Arc<TorClient>` — and arti's exclusive
  state-dir lock — survives until the last in-flight connection that had
  already cloned it finishes, which for a long-lived connection (e.g. a
  persistent Telegram session) can be hours. After 7 successful rebuilds
  over 16 hours on one deployment, the 8th collided with a still-draining
  generation from several cycles earlier and failed with `"another
  instance of Arti has the lock"` on every retry, permanently — the
  watchdog could never recover on its own. Fixed by replacing the fixed
  pair with a pool of 6 candidate directories, each probed with a
  non-blocking `fslock-guard` lock check before use (the same crate
  `tor-persist` itself locks with) so a rebuild always lands on a slot
  that is genuinely free right now, tolerating however many prior
  generations are still draining, up to the size of the pool.
- The watchdog could rebuild into a self-inflicted outage: a rebuilt
  `TorClient` lands in a cold rebuild-slot directory whose bridge-descriptor
  cache starts empty, so its guards report "unsuitable to purpose" for
  several minutes while it re-fetches descriptors over the network — but
  arti's readiness signal only covers directory bootstrap, not bridge
  descriptors, so the watchdog swapped this in immediately, replacing a
  live (if degraded) client with one guaranteed unable to carry traffic.
  One production incident saw a 12-minute outage this way, and the
  watchdog's own periodic re-triggering (since the swapped-in client also
  couldn't recover) made it worse rather than better. Fixed on four fronts:
  a canary check retries the most recent successful `(host, port)` through
  the rebuilt client before trusting it enough to swap in (a failed canary
  now keeps the old client running instead); every failed `TorTunnel::
  connect` is classified by `tor_error::ErrorKind` into three buckets
  (exit-side timeout, guard/descriptor exhaustion, genuine circuit-build
  timeout), and the watchdog now declines to rebuild when the window is
  dominated by the first two — a rebuild cannot fix either, and for
  guard exhaustion it actively reproduces it; the rebuild's target slot has
  its bridge-descriptor cache warmed from the primary directory before
  construction, so it starts with the same advantage a cold process
  restart already got for free; and the "attempts this tick" trigger
  condition now requires at least 3 attempts instead of 1, so a single
  stray retry cannot arm a rebuild decision.
- The watchdog's rebuild-slot pool (see the entries above) existed to work
  around one thing: there was no public API to force-invalidate a stale Tor
  channel, so the only known reset was building a second, whole `TorClient`
  in a sibling state directory and swapping it in once it proved usable.
  Everything else about that design was compensating for the side effects
  of that workaround — a rebuilt client landed in a *cold* state directory
  with an empty bridge-descriptor cache, so a hand-written warm-up step
  (`warm_slot_bridge_desc_cache`) copied `BridgeDescs` rows out of
  `tor-dirmgr`'s *private*, version-specific sqlite schema, something its
  own doc comment already flagged as "an internal implementation detail
  that could shift on an arti upgrade"; and because `TorHandle::swap` only
  drops its own reference while the outgoing client's state-dir lock can
  survive for hours (a long-lived connection still holding a clone open),
  a single sibling directory was not enough, requiring a pool of 6
  candidate directories each probed with a non-blocking `fslock-guard` lock
  check before use — and still capable of exhausting the whole pool if
  enough generations were draining at once. Replaced by vendoring
  `tor-chanmgr` 0.43.0 and adding `ChanMgr::terminate_all_channels()` to it
  (force-closes every channel the *live* client's channel manager tracks,
  reusing the same iteration `expire_channels()` already does, without
  touching guard/circuit state), exposed through `arti-client`'s
  `TorClient::chanmgr()` (gated behind the `experimental-api` cargo
  feature, now enabled) and a new `TorTunnel::terminate_all_channels()` on
  the wrapper. The watchdog now reacts to the exact same trigger
  conditions (stale window, attempt/failure-kind counters, the
  `should_decline_rebuild` signature gate, `MIN_ATTEMPTS_TO_TRIGGER`) by
  terminating the live client's channels in place — same client, same state
  directory, same already-warm guard/bridge-descriptor cache, no second
  `TorClient` to construct, canary-test, or dispose of — and lets arti's
  `ChanMgr::get_or_launch` build fresh channels the next time one is
  requested. The canary (`verify_usable`, unchanged) still runs after
  termination to judge whether the reconnect actually worked, feeding the
  same `consecutive_failures`/cooldown backoff as before; there is simply
  no longer a second client for it to gate a swap on. This removes the
  cold-cache trade-off entirely (no cold rebuild-slot state directory ever
  exists, so there is nothing for it to be cold), along with the
  `fslock-guard` and `rusqlite` direct dependencies of `socks5-proxy`
  (both remain in the dependency tree transitively via `tor-dirmgr`/
  `tor-persist`, just no longer used by this crate's own code).
- Even with the rebuild-slot pool gone (see above), the underlying reason
  arti itself could report "ready for traffic" while still unable to build a
  single data circuit remained: `BootstrapStatus::ready_for_traffic()`
  considered only directory-bootstrap completeness, with no notion of
  whether any guard actually had a usable descriptor
  (`dir_info_missing`) — the root cause analyzed in
  `docs/upstream/guard-exhaustion-watchdog-spiral.md`. Fixed by vendoring
  `tor-guardmgr` 0.43.0 and `arti-client` 0.43.0 as a mandatory pair (neither
  half is useful alone). `tor-guardmgr` gains
  `GuardSet::any_guard_usable_for_traffic()` (true iff at least one guard in
  the active sample is usable and has complete directory information) and
  `GuardMgr::usable_guard_events()`, a `postage::watch`-backed stream
  (mirroring the crate's existing `skew_events()` plumbing) republishing this
  aggregate on every guard-sample refresh. `arti-client` wires this in as a
  fourth event source in `RunningInner::new`/`report_status` (alongside
  `conn_status`/`dir_status`/`skew_status`) and `ready_for_traffic()` now
  requires it as a third conjunct, defaulting to `false` so a freshly
  constructed client is never "ready" before the first guard-sample refresh
  reports in. The watchdog's `verify_usable` canary is left in place for
  now — it may become partly redundant once this is observed live, but that
  retirement is a separate, later decision pending field data.
- The stdin-EOF workaround thread added earlier for the zombie PT-child
  problem (see the `ptrs-gesher-lyrebird` 0.5.1 entry above) masked a bug
  in our own `ptrs-gesher` project rather than fixing it — `ptrs-gesher`
  is our sibling repository, not a true third-party upstream, so the
  right place for the fix was there. `ptrs-gesher-lyrebird` 0.5.2 (bumped
  from `"0.5"`, no `Cargo.toml` change needed) now honors
  `TOR_PT_EXIT_ON_STDIN_CLOSE` itself via a proper `CancellationToken`
  wired into its own graceful-shutdown `select!` loop, verified by a
  process-level integration test that launches the real binary and
  asserts it exits on stdin close. The now-redundant workaround thread in
  `main.rs`'s PT-child branch is removed.
- The PT channel-build timeout was too tight for a healthy-but-slow
  bridge. `tor-chanmgr`'s `connect_via_transport` armed a single TOTAL
  timeout around the whole channel build — 5s for a `is_direct()`
  channel, 10s for everything else — and `is_direct()` is false for
  *every* pluggable-transport channel, so in this client's bridge-only
  operation 100% of channel builds were bounded by that 10s ceiling.
  That ceiling has to cover the entire PT handshake (TCP connect to the
  bridge + obfs4/webtunnel client handshake + Tor TLS + Tor link
  handshake, ~10+ round trips), which a high-latency or
  congested-but-healthy bridge path cannot fit — and because
  `Error::ChanTimeout` maps to `RetryTime::Immediate`, the guard manager
  retried at once and hit the same 10s ceiling again, looping instead of
  giving the slow path the longer single wait it needed. Fixed by
  vendoring `tor-chanmgr` 0.43.0's connect path and raising the PT
  (non-direct) total 10s → 45s (the direct-relay total stays at 5s),
  extracted as a unit-tested `connect_build_timeout(is_direct)` helper.
  This is a single generous **total**, deliberately not the idle/total
  split applied earlier to `tor-dirclient`'s directory download: that
  split works only because the download is a read loop with per-byte
  progress, whereas here the slow phase (the PT handshake) is entirely
  inside the opaque `TransportImplHelper::connect` call with no progress
  callback — the phase-completion boundaries visible at this level
  bracket the PT handshake rather than sample within it, so an idle
  timer reset there would degenerate to a per-phase total. A genuine
  idle/total fix for the PT handshake belongs one layer down, in the PT
  transport (`tor-ptmgr` / the PT child) emitting progress ticks.
- `tor-guardmgr` could permanently (and persistently, across restarts)
  disable one of the few hand-configured bridges with no automatic recovery
  path. `record_indeterminate_result()` sets `Guard::disabled` once a guard's
  *lifetime* indeterminate-failure ratio (`n_indeterminate / (n_successes +
  n_indeterminate)`, sampled past 15 observations) crosses `0.7`. That
  `disabled` field is serialized to the state file and nothing in the crate
  ever clears it — its own TODO concedes "we'll need a way to make ancient
  history expire" but no such mechanism exists. `GuardStatus::Indeterminate`
  is exactly the "circuit failed beyond the guard" class (second-hop/exit
  timeouts) that the guard-exhaustion incident logged by the hundred per
  minute; in bridge-only operation, where traffic splits across 2-6 bridges
  instead of thousands of sampled relays, one such storm can push a bridge
  over the threshold and take it out of rotation *for good*. The detection
  logic and its threshold are left untouched (they are an upstream-tuned
  path-bias defense); instead a manual override hook is added so an
  application-level watchdog can deliberately re-enable disabled bridges on
  its own policy ("too few usable bridges remain"). `Guard::reset_disabled()`
  clears `disabled` **and** resets `CircHistory`/`suspicious_behavior_warned`
  (otherwise the next indeterminate result would immediately re-trip the
  threshold on the stale numerator), surfaced as
  `GuardSet::reset_disabled_guards()` (counting re-enabled guards, leaving
  healthy guards' history untouched), `GuardMgr::reset_disabled_guards()`,
  and a `TorClient::reset_disabled_guards()` passthrough (gated
  `experimental-api`, mirroring the existing `dirmgr()`/`circmgr()`/
  `chanmgr()` accessors). Parallels `tor-chanmgr`'s
  `terminate_all_channels()` as a second application-reachable escape hatch
  for an upstream mechanism that, in a small bridge-only pool, can strand a
  resource with no auto-recovery.
- A panic inside `tor-dirmgr`'s `SharedMutArc::mutate()` (e.g. an edge-case
  microdescriptor parse in `DirMgr`'s `add_microdesc` loop, which runs roughly
  hourly) permanently bricked the shared netdir handle. All four lock sites in
  `shared_ref.rs` (`replace`/`clear`/`get`/`mutate`) used
  `.write()/.read().expect("Poisoned lock for directory reference")` on a plain
  `std::sync::RwLock`; a panic inside `mutate()`'s closure poisons that lock
  forever, and `.expect()` then re-panics on every subsequent access. The
  process stays alive (a panic in a spawned tokio task doesn't tear down the
  runtime) but every later directory read panics in its own task — silent
  permanent degradation until a manual restart, exactly what this long-lived
  headless deployment tries to avoid. Fixed by vendoring `tor-dirmgr` 0.43.0's
  `shared_ref.rs` and replacing the four `.expect(...)` sites with
  `.unwrap_or_else(|e| e.into_inner())` — the same recover-from-poisoned-lock
  pattern already used in this repo's `tor_watchdog.rs`. `into_inner()` hands
  back the guard over whatever data survived the panic; it does **not** roll
  back a partial mutation made before the panic (a full `catch_unwind` rollback
  was deliberately left as the larger, optional second step). Regression test
  added: a panicking closure no longer poisons the next `get()`/`mutate()`.
- `tor-dirmgr`'s `sqlite_error_kind()` (`err.rs`) classified `SQLITE_BUSY` /
  `SQLITE_LOCKED` (`rusqlite::ErrorCode::DatabaseBusy`/`DatabaseLocked`) as
  `ErrorKind::Internal`, so `impl From<rusqlite::Error> for Error` wrapped them
  as `tor_error::Bug` ("sqlite detected bug") and `bootstrap_action()` then
  treated them as `Fatal`. On a long-lived Windows desktop process the
  directory cache db is routinely locked for a few milliseconds by antivirus
  real-time scanning, Windows Search indexing, or OneDrive/backup sync over
  the cache directory — exactly the transient, fully-recoverable contention
  that `SQLITE_BUSY`/`SQLITE_LOCKED` semantically mean ("try again later"). A
  transient file lock was thus mislabeled and mis-handled as a programming
  bug, fatally aborting bootstrap. Fixed by reclassifying `DatabaseBusy` /
  `DatabaseLocked` into `ErrorKind::CacheAccessFailed` — the same bucket
  already used for the analogous environmental cache-access failures
  (`FileLockingProtocolFailed`, `SystemIoFailure`, `CannotOpen`, ...) — so
  they become a plain `Error::SqliteError` instead of `Error::Bug`. (Both
  variants still map to `BootstrapAction::Fatal`, so this is primarily an
  honest-classification fix that stops a transient lock from being reported
  as a "detected bug" and sets up correct semantics for a future retry-with-
  backoff, deliberately left as the larger, optional second step.)
  `OperationInterrupted` / `OperationAborted` were deliberately left in
  `Internal`: they are explicit cancel/abort signals, not file-lock
  contention. Regression tests added covering both the direct classification
  and the end-to-end `From<rusqlite::Error>` path.
- `arti-client`'s intentional ["fast zombies"](https://spec.torproject.org/proposals/266-removing-current-obsolete-clients.html)
  shutdown (Tor proposal 266: exit if the live consensus marks a subprotocol
  our build lacks as required) called `std::process::exit(1)` after only an
  `eprintln!` to stderr — invisible in this project's deploy model, which has
  no supervisor/systemd/Docker to notice the process died. Not weakening the
  shutdown itself (deliberate, same reasoning as the `safelog` item below);
  added a `FatalProtocolErrorHandler` hook (`TorClientBuilder::
  fatal_protocol_error_handler()`) invoked immediately before the existing
  `eprintln!`/`sleep`/`process::exit(1)` sequence, which is otherwise
  unchanged. `packages/arti-wrapper` installs a `tracing::error!` marker as
  the hook on every `TorClient` construction path, so the event now lands in
  this project's normal logging pipeline instead of being silent.

- The bridge-descriptor fetch in `tor-guardmgr` was throttled to the top
  `maximum = max(data_parallelism, 2)` guards even during a total
  guard-exhaustion state, where that conservative cap is itself the
  bottleneck. When every guard is descriptor-naked, the eligible guards are
  still listed, reachable, and not in backoff (a failed descriptor fetch is
  invisible to the guard layer), so they all pass `descriptors_to_request`'s
  filter and are then truncated by `take(maximum)` — leaving a client
  requesting descriptors for only its top 2 bridges while 20+ others that
  could recover it are never asked. This is the exact mechanism behind the
  12-minute outage in `docs/upstream/guard-exhaustion-watchdog-spiral.md`
  §2.4, and it also starved the `tor-dirmgr` parallelism raise to 12
  (separate fix above): the manager can only fetch bridges the guard layer
  hands it via `set_bridges`, so a 12-wide ceiling was never reached while
  only 2 were ever requested. Fixed by widening the cap to the whole eligible
  sample only while `GuardSet::any_guard_usable_for_traffic()` is false (the
  exhaustion emergency), then snapping back to the conservative top-N the
  moment the first guard's descriptor arrives and it becomes usable. Safe
  against flooding because the lower layer (`tor-dirmgr`'s `BridgeDescMgr`)
  independently caps concurrent fetches and backs off per-bridge retries, so
  requesting more candidates here cannot exceed that budget — it only stops
  starving it. Additive: one conditional inside `descriptors_to_request`, no
  signature change.

### Known limitations

- Bridges whose TCP reachability probe passes but whose obfs4/webtunnel
  handshake times out (`lyrebird: handshake failed: HandshakeTimeout`)
  cannot currently be attributed to a specific bridge for faster pruning:
  `tor-chanmgr`/`tor-circmgr` wrap the failing peer in
  `safelog::BoxSensitive`, which renders as `[scrubbed]` by design, and
  `tor-ptmgr` re-emits the PT child's own log lines as unstructured text.
  Working around this would require either disabling arti's safe-logging
  (a security regression) or parsing the PT child's free-form log text
  (brittle, not under our control). The existing TCP-probe and
  `circuit_fails` (guard-reachability) counters remain the only pruning
  signals for such bridges, which is why a TCP-alive/handshake-dead bridge
  is pruned more slowly than a fully dead one.
