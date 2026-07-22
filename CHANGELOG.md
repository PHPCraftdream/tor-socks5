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
