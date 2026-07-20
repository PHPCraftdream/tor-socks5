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
