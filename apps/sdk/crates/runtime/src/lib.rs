//! The runtime module tree of the socks5-proxy binary, moved verbatim into
//! this crate (SDK-6; docs/plans/sdk-coverage-plan.md). The Tor-client API
//! step SDK-9 is open: `tor_setup`, `pt` and the watchdog
//! status/handle surface (see the README's "Tor client API (SDK-9)"). Bridge
//! health writing/observation (SDK-7) and the bridge manager (SDK-8) are
//! still closed.
//!
//! The `test-seams` feature (dev-only, enabled by consumers' dev-dependencies,
//! R10) exposes the `test_seams` module so cross-crate tests can exercise the
//! same seams the binary's own tests use. It must never be enabled in
//! default/full builds.

#[path = "tor/arti_observability.rs"]
pub mod arti_observability;

#[path = "bridges/bridge_maintenance.rs"]
pub mod bridge_maintenance;

#[path = "bridges/bridge_maintenance/bridge_rank.rs"]
mod bridge_rank;

#[path = "bridges/bridge_store_writer.rs"]
pub mod bridge_store_writer;

#[path = "bridges/bridge_verifier.rs"]
pub mod bridge_verifier;

#[path = "bridges/bridge_warmer.rs"]
pub mod bridge_warmer;

#[path = "bridges/candidate_pool.rs"]
pub mod candidate_pool;

mod config;

#[path = "tor/conn_health.rs"]
pub mod conn_health;

#[path = "fetch/fetch_merge/fetch_merge.rs"]
pub mod fetch_merge;

#[path = "fetch/seed.rs"]
mod seed;

pub mod pt;

#[path = "tor/tor_setup.rs"]
pub mod tor_setup;

#[path = "tor/tor_watchdog/tor_watchdog.rs"]
pub mod tor_watchdog;

#[cfg(any(test, feature = "test-seams"))]
#[path = "tor/test_seams.rs"]
pub mod test_seams;

#[cfg(test)]
#[path = "tor/ts19_tests.rs"]
mod ts19_tests;

#[path = "bridges/bridge_maintenance/workers.rs"]
pub mod workers;
