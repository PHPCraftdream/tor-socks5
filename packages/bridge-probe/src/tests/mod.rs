mod dns_cache_tests;
mod dns_flush_save_race_tests;
mod dns_invalidation_tests;
mod dns_registry_tests;
mod dns_save_regression_tests;
mod dns_save_tests;
mod dns_temp_ownership_tests;
mod dns_timestamp_tests;
mod probe_coalesce_regression_tests;
mod probe_coalesce_tests;
mod probe_identity_tests;
mod probe_ordering_tests;
mod probe_race_tests;
mod transport_tests;

use bridge_line::BridgeLine;
use std::str::FromStr;

/// Serializes every test that touches ANY process-global DNS state. Hold it
/// for the whole test body.
///
/// That state is one interdependent whole, which is why this is one lock and
/// not several:
///
/// - the live DoH cache and the process-wide disk fallback store.
///   `save_persisted_dns_cache` merges the WHOLE fallback store into the file
///   it writes, and `forget_dns_answer` only forgets the live cache -- so a
///   parallel test's store insert landing between another test's `remember`
///   and `forget` re-publishes a dropped host (see
///   `superseded_save_must_not_publish_stale_snapshot`);
/// - `DNS_NETWORK_GENERATION`, which `flush_dns_cache` bumps;
/// - the in-flight `INFLIGHT_DOH` registry and the fake wave-search seam.
///
/// This used to be two separate locks -- this one for the stores and a
/// `FAKE_WAVE_LOCK` for the registry and the fake seam -- and the gap between
/// them was a real defect: the registry is keyed by `(host, generation)`, so a
/// flush test bumping the generation in parallel made a registry test's joiner
/// look up a different key, miss the owner's cell, and start a lookup that
/// parked forever on a channel nobody would release. It failed only on the
/// macOS CI runner, where the test order happened to interleave the two.
/// Splitting this lock again means re-deciding which parts of the DNS globals
/// are provably independent; they were not.
pub(crate) static DNS_GLOBAL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn bridge_for(addr: std::net::SocketAddr) -> BridgeLine {
    BridgeLine::from_str(&format!(
        "obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    ))
    .expect("synthetic bridge line parses")
}
