mod dns_cache_tests;
mod dns_invalidation_tests;
mod dns_registry_tests;
mod dns_save_regression_tests;
mod dns_save_tests;
mod dns_timestamp_tests;
mod probe_coalesce_regression_tests;
mod probe_coalesce_tests;
mod probe_identity_tests;
mod probe_ordering_tests;
mod probe_race_tests;
mod transport_tests;

use bridge_line::BridgeLine;
use std::str::FromStr;

/// Serializes every test that mutates or seeds the process-global DNS
/// stores: the live DoH cache and, critically, the process-wide disk
/// fallback store. `save_persisted_dns_cache` merges the WHOLE fallback
/// store into the file it writes, and `forget_dns_answer` only forgets the
/// live cache -- so a parallel test's store insert leaking into the window
/// between another test's `remember` and `forget` re-publishes a dropped
/// host (see `superseded_save_must_not_publish_stale_snapshot`). Any test
/// calling save/load/seed or `disk_fallback_store` directly -- and
/// `flush_dns_cache`, which clears the shared live cache -- must hold this
/// lock for its whole body. Same pattern as `FAKE_WAVE_LOCK` in
/// `probe_coalesce_tests.rs`.
static DNS_GLOBAL_STORE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn bridge_for(addr: std::net::SocketAddr) -> BridgeLine {
    BridgeLine::from_str(&format!(
        "obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    ))
    .expect("synthetic bridge line parses")
}
