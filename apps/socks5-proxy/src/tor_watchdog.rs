//! Stale-channel watchdog: detects Tor channels left half-open by a
//! silent network change and terminates them in place, letting arti
//! reconnect over the same already-bootstrapped `TorClient`.
//!
//! ## The problem this solves
//!
//! `arti-client` / `tor-chanmgr` 0.43 has no hook on network-change events,
//! and `TorClient::reconfigure()` does **not** reset channels — it only
//! re-parameterises padding/KIST on already-open ones. The only automatic
//! channel expiry (`continually_expire_channels`) closes a channel that has
//! been idle for 180–270 s; a channel against which circuits are *actively*
//! (but hopelessly) being attempted is never idle, so it is never expired.
//!
//! The dead-channel signal in arti is an OS-level TCP error (RST/EOF/write
//! failure). On a quiet Wi-Fi handoff the socket stays half-open and the
//! default Windows TCP keepalive is measured in hours, so that signal may
//! never arrive.
//!
//! ## How it heals
//!
//! Every SOCKS5 CONNECT through Tor bumps an attempt counter; a successful
//! one stamps `last_success`. A background task (see [`spawn_tor_watchdog`])
//! periodically checks: if no circuit succeeded within the stale window
//! **while attempts keep coming** and at least one bridge is still
//! TCP-reachable (so this is not the bridge-maintenance loop's problem), it
//! calls [`arti_wrapper::TorTunnel::terminate_all_channels`] on the *live*
//! `TorTunnel` — the same client, in the same state directory, with the
//! same already-warm guard/bridge-descriptor cache — and lets arti's own
//! `ChanMgr::get_or_launch` build fresh channels the next time one is
//! requested. A cooldown prevents a rebuild storm when this does not help
//! (a genuine network block).
//!
//! ## Why this replaced the old rebuild-slot-pool design
//!
//! An earlier version of this watchdog reacted to the same trigger
//! conditions by constructing a brand-new `TorTunnel` in one of a small pool
//! of sibling "rebuild slot" state directories, warming its bridge-
//! descriptor sqlite cache from the primary directory by hand, canary-
//! testing it, and only then swapping it in for the old client. That design
//! existed to work around exactly one problem: there was no public API to
//! force-invalidate a channel, so the only known reset was "build a whole
//! new `TorClient`". Everything else about it was compensating for the
//! side effects of that workaround —
//!
//! - A rebuilt client landed in a *cold* state directory, so guards started
//!   "unsuitable to purpose" until bridge descriptors were re-fetched over
//!   the network, which could take minutes — the sqlite-warm-up step
//!   (`warm_slot_bridge_desc_cache`, since removed) tried to paper over this
//!   by hand-copying `BridgeDescs` rows out of `tor-dirmgr`'s *private*,
//!   version-specific on-disk schema — the code's own doc comments already
//!   flagged this as "an internal implementation detail that could shift on
//!   an arti upgrade".
//! - A single fixed sibling directory assumed the outgoing client's state-
//!   dir lock was always free to reuse; it is not — `TorHandle::swap` only
//!   drops its own reference, and the underlying `Arc<TorClient>` (and
//!   arti's exclusive lock) survives until the last long-lived connection
//!   that had cloned it finishes, which can be hours. This required a pool
//!   of `REBUILD_SLOT_COUNT` candidate directories, each probed with a
//!   non-blocking `fslock-guard` lock check (`slot_is_free`/`pick_free_slot`,
//!   since removed) before use — fragile in its own right (hardcoded
//!   `cache/dir.lock` / `state/state/state.lock` paths) and still capable of
//!   exhausting the whole pool if enough generations were draining at once.
//!
//! [`tor_chanmgr::ChanMgr::terminate_all_channels`] (vendored — see
//! `vendor/tor-chanmgr/src/lib.rs` and `vendor/README.md`) removes the
//! premise these workarounds existed for: it force-closes every channel the
//! *live* client's channel manager tracks without building anything new, so
//! there is no cold cache, no second state-dir lock to juggle, and no slot
//! pool to exhaust. `TorClient::chanmgr()` is behind `arti-client`'s
//! `experimental-api` feature cargo flag, which this workspace now enables.
//!
//! ## Judging success without a second client to canary
//!
//! The old design canary-tested the *new* client (via [`verify_usable`])
//! before trusting it enough to swap in, because there were two clients in
//! play and only one of them should survive. Here there is only ever one
//! client — the same one, with its channels reset — so "swap in on success"
//! has no meaning any more. What still needs answering is the same question
//! the old canary answered: did this actually help? We reuse the identical
//! mechanism ([`verify_usable`], unchanged: retry the most recent
//! successful `(host, port)` under a timeout) *after* calling
//! `terminate_all_channels`, and feed its answer into the exact same
//! `consecutive_failures`/cooldown machinery the rebuild path used — a
//! successful reconnect resets the counter, a failure extends the cooldown.
//! This keeps the operational behavior (backoff under a genuinely blocked
//! network, quick recovery otherwise) identical to before, without a
//! parallel client to construct or dispose of.
//!
//! ## Why "attempts are failing" isn't enough on its own
//!
//! Terminating channels only forces a reconnect — it does nothing for a
//! healthy Tor stack whose *exits* went quiet, or whose guards are
//! temporarily unsuitable; retrying those the exact same way changes
//! nothing. This is the mechanism analyzed in
//! docs/upstream/guard-exhaustion-watchdog-spiral.md: a rebuild triggered by
//! exit-side timeouts, not a stale channel, made an outage worse rather than
//! fixing it. `classify_and_record` (fed from `server.rs` on every failed
//! `TorTunnel::connect`) and [`should_decline_rebuild`] add a fourth trigger
//! condition — a signature gate — that declines to act when the window's
//! failures are dominated by `RemoteNetworkTimeout` or `TorAccessFailed`
//! rather than `TorNetworkTimeout`, since only the latter is the "zombie
//! channel" signature a channel reset can actually fix.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arti_wrapper::TorTunnel;
use bridge_line::BridgeLine;
use time::OffsetDateTime;
use tokio::sync::{Notify, RwLock};
use tracing::{debug, info, warn};

use crate::bridge_warmer::{candidates_with_health, Health};
use crate::config::{Config, WatchdogConfig};
use bridge_store::BridgeStore;

#[path = "tor_watchdog_health.rs"]
mod health;
#[path = "tor_watchdog_runtime.rs"]
mod runtime;

#[allow(unused_imports)]
pub(crate) use health::BridgeRefresh;
#[allow(unused_imports)]
pub use health::{classify_and_record, TorHandle, TorHealth};
pub use runtime::{spawn_bridge_failover_watchdog, spawn_tor_watchdog};

#[cfg(test)]
#[path = "tor_watchdog_tests.rs"]
mod tor_watchdog_tests;
