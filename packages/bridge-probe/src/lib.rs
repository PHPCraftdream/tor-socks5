//! Parallel reachability probe for a list of bridges.
//!
//! Arti's guard manager picks one bridge at a time, retries it with long
//! back-offs, and only then moves on — fine for stability, bad for cold
//! start when half the configured bridges are dead. We probe TCP
//! reachability of every bridge in parallel, then hand arti the list of
//! responders sorted by latency, so the fastest live bridge becomes the
//! first one arti tries.
//!
//! For most transports the TCP target is `bridge.addr`, but webtunnel
//! is special: the bridge-line `<addr>:<port>` is cosmetic and the real
//! target lives in the `url=` parameter (with an optional `addr=` override).
//! `resolve_probe_target` computes the correct `(host, port)` pair per
//! transport before the TCP handshake.

#[allow(unused_imports)]
use std::collections::{BTreeMap, HashMap};
#[allow(unused_imports)]
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering as AtomicOrdering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bridge_line::BridgeLine;
#[allow(unused_imports)]
use futures::stream::{self, StreamExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
#[allow(unused_imports)]
use tokio::time::timeout;

mod dns;
mod probe;

pub use dns::{
    best_known_answer, dns_hostname_of, flush_dns_cache, format_dns_hint_line,
    load_persisted_dns_cache, parse_dns_hint_line, save_persisted_dns_cache, seed_disk_fallback,
    DnsHint, ResolverPolicy, DNS_HINT_PREFIX,
};
pub use probe::{
    probe_all, probe_all_with_policy, probe_and_sort, probe_and_sort_with_policy, probe_one,
    probe_one_with_policy, probe_round_with_policy, probe_until, probe_until_with_policy,
    resolve_addrs, usable_for_tor, webtunnel_endpoint_identity, Outcome, ProbeRound, Report,
    WebtunnelEndpointIdentity,
};

#[cfg(test)]
mod dns_publish_pause;
#[cfg(test)]
mod tests;
