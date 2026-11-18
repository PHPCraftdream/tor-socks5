//! H19.3 coverage for the refresh/top-up orchestration in [`super`]:
//! `refresh_candidate_pool` and `top_up_working_with_pt` take a real
//! `&TorTunnel`, so these tests use `TorTunnel::create_unbootstrapped_with`
//! over a fresh tempdir state (the offline pattern of
//! `bridge_manager::bridge_producers_tests`): the tunnel never bootstraps,
//! every fetch over it fails deterministically, and the tests pin what the
//! failure path must and must not touch on disk.

use super::*;
use crate::config::BridgeSource;
use std::sync::Once;

/// Install rustls's process-wide `CryptoProvider` once (see
/// `tor_watchdog_tests::ensure_crypto_provider` for the rationale: a fresh
/// empty `state_dir` reaches arti's directory-manager setup, which expects a
/// provider to be installed).
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A real (never-bootstrapping) tunnel for signatures that require one.
fn unbootstrapped_tunnel(dir: &tempfile::TempDir) -> TorTunnel {
    ensure_crypto_provider();
    let settings = arti_wrapper::Settings {
        state_dir: Some(dir.path().join("arti-state")),
        ..Default::default()
    };
    TorTunnel::create_unbootstrapped_with(settings).expect("synchronous, no-I/O construction")
}

fn source(label: &str, url: &str) -> BridgeSource {
    BridgeSource {
        label: label.to_owned(),
        url: url.to_owned(),
        headers: Vec::new(),
        cookies: Vec::new(),
        allow_credentials_cross_origin: false,
    }
}

fn candidate(last_octet: u32) -> BridgeLine {
    format!("10.0.3.{last_octet}:443 4444444444444444444444444444444444444444")
        .parse()
        .expect("valid candidate bridge line")
}

/// Write a config file and return its path.
fn config_fixture(dir: &tempfile::TempDir, cfg: &Config) -> std::path::PathBuf {
    let path = dir.path().join("proxy.ktav");
    cfg.write(&path).expect("write config");
    path
}

/// H19.3: refresh with no configured sources is a no-op — `Ok(0)` and the
/// pool file is not even created (no transaction, no lock, no fetch).
///
/// ROLLBACK THAT FAILS THIS: someone moving the empty-sources early return
/// below the pool transaction (or fetching unconditionally) would create the
/// pool file here.
#[tokio::test]
async fn refresh_without_sources_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    // The default config carries the built-in sources: clear them, or this
    // test would fetch from the real network.
    let mut cfg = Config::default();
    cfg.bridges.sources.clear();
    let path = config_fixture(&dir, &cfg);
    let pool_path = CandidatePool::resolve_path(&path);
    let tor = unbootstrapped_tunnel(&dir);

    let added = refresh_candidate_pool(&tor, &cfg, &path, Duration::from_secs(1))
        .await
        .expect("no sources is success");
    assert_eq!(added, 0);
    assert!(!pool_path.exists(), "pool must not be created");
}

/// H19.3 atomicity regression: a refresh whose source fetch fails over the
/// (unbootstrapped) tunnel must leave the on-disk pool byte-identical —
/// `fetch_sources` returns no bridges, so the pool transaction never runs.
/// (`refresh_candidate_pool` reports `Ok(0)` here: per-source failures are
/// logged, not propagated — the error leg only exists for pool-transaction
/// or config-migration failures.)
///
/// ROLLBACK THAT FAILS THIS: writing a partial pool before (or regardless
/// of) the fetch outcome — e.g. merging an empty-but-nonzero fetch batch or
/// saving the pool outside the transaction — changes the pool file here.
#[tokio::test]
async fn failed_fetch_leaves_the_pool_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.bridges.sources = vec![source("dead", "http://127.0.0.1:1/bridges.txt")];
    let path = config_fixture(&dir, &cfg);
    let pool_path = CandidatePool::resolve_path(&path);
    let pooled = candidate(1);
    let mut pool = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(pool.merge([pooled], &HashSet::new()), 1);
    pool.save().unwrap();
    let before = std::fs::read(&pool_path).unwrap();
    let tor = unbootstrapped_tunnel(&dir);

    let added = refresh_candidate_pool(&tor, &cfg, &path, Duration::from_secs(1))
        .await
        .expect("failed sources are logged, not fatal");
    assert_eq!(added, 0);
    assert_eq!(
        std::fs::read(&pool_path).unwrap(),
        before,
        "a failed fetch must not touch the pool file"
    );
}

/// H19.3: sources that only name retired (upstream-404) URLs are filtered
/// out before any network work — the refresh must neither fetch (nothing
/// left to fetch), nor create a pool, nor rewrite the config.
///
/// ROLLBACK THAT FAILS THIS: dropping the `retired_source` filter in
/// `fetch_sources` would attempt a doomed fetch (outcome logged, still
/// `Ok(0)` — so the pinned config-bytes assertion is the guard) and dropping
/// the `config_stale` migration gating would rewrite the config file here.
#[tokio::test]
async fn refresh_with_only_retired_sources_never_touches_disk() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.bridges.sources = vec![source(
        "tor-browser",
        "https://gitlab.torproject.org/tpo/applications/tor-browser/-/raw/main/projects/common/bridges_list.obfs4.txt",
    )];
    let path = config_fixture(&dir, &cfg);
    let config_bytes = std::fs::read(&path).unwrap();
    let tor = unbootstrapped_tunnel(&dir);

    let added = refresh_candidate_pool(&tor, &cfg, &path, Duration::from_secs(1))
        .await
        .expect("retired-only sources are success");
    assert_eq!(added, 0);
    assert!(!CandidatePool::resolve_path(&path).exists());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        config_bytes,
        "retired-only sources must not migrate the config (nothing was fetched)"
    );
}

/// H19.3: `top_up_working_with_pt` with `target == 0` returns `Ok(0)`
/// immediately — no drain, no refresh, no pool or config interaction, even
/// when a pool candidate and a source are configured.
///
/// ROLLBACK THAT FAILS THIS: losing the `if target == 0` early return would
/// drain the pool (probing the candidate over the network) — observable only
/// as slowness today, so this test pins the config/pool files instead of
/// timing.
#[tokio::test]
async fn top_up_zero_target_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.bridges.sources = vec![source("x", "http://127.0.0.1:1/bridges.txt")];
    let path = config_fixture(&dir, &cfg);
    let pool_path = CandidatePool::resolve_path(&path);
    let mut pool = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(pool.merge([candidate(2)], &HashSet::new()), 1);
    pool.save().unwrap();
    let pool_before = std::fs::read(&pool_path).unwrap();
    let config_before = std::fs::read(&path).unwrap();
    let tor = unbootstrapped_tunnel(&dir);

    let promoted = top_up_working_with_pt(&tor, &cfg, &path, 0, crate::pt::PtBinary::Environment)
        .await
        .expect("target 0 is success");
    assert_eq!(promoted, 0);
    assert_eq!(std::fs::read(&pool_path).unwrap(), pool_before);
    assert_eq!(std::fs::read(&path).unwrap(), config_before);
}

/// H19.3: an empty pool and no sources — the drain finds nothing and the
/// "pool short" refresh leg is skipped (sources empty), so `Ok(0)` with the
/// config untouched and no pool file created.
///
/// ROLLBACK THAT FAILS THIS: dropping the `!cfg.bridges.sources.is_empty()`
/// guard in `top_up_working_with_pt` would refresh unconditionally (fetching
/// over the dead tunnel) and could create pool entries from nothing.
#[tokio::test]
async fn top_up_with_empty_pool_and_no_sources_skips_the_refresh_leg() {
    let dir = tempfile::tempdir().unwrap();
    // The default config carries the built-in sources: clear them, or this
    // test would fetch from the real network.
    let mut cfg = Config::default();
    cfg.bridges.sources.clear();
    let path = config_fixture(&dir, &cfg);
    let config_before = std::fs::read(&path).unwrap();
    let tor = unbootstrapped_tunnel(&dir);

    let promoted = top_up_working_with_pt(&tor, &cfg, &path, 1, crate::pt::PtBinary::Environment)
        .await
        .expect("nothing to drain is success");
    assert_eq!(promoted, 0);
    assert!(!CandidatePool::resolve_path(&path).exists());
    assert_eq!(std::fs::read(&path).unwrap(), config_before);
}

/// H19.3: pool short (one candidate, unreachable offline) and sources
/// configured — the drain probes and discards the dead candidate, the
/// refresh leg runs (fetch fails over the unbootstrapped tunnel, logged not
/// fatal), the second drain finds nothing, and the result is `Ok(0)` with
/// the working config untouched: a failed replenishment never mutates the
/// bridge list.
///
/// ROLLBACK THAT FAILS THIS: promoting an unreachable candidate (e.g. an
/// admission check that skips the probe result) would add the candidate to
/// the config and the config-bytes assertion fails.
#[tokio::test]
async fn top_up_short_pool_exhausts_sources_and_never_touches_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.bridges.sources = vec![source("dead", "http://127.0.0.1:1/bridges.txt")];
    let path = config_fixture(&dir, &cfg);
    let pool_path = CandidatePool::resolve_path(&path);
    let mut pool = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(pool.merge([candidate(3)], &HashSet::new()), 1);
    pool.save().unwrap();
    let config_before = std::fs::read(&path).unwrap();
    let tor = unbootstrapped_tunnel(&dir);

    let promoted = top_up_working_with_pt(&tor, &cfg, &path, 1, crate::pt::PtBinary::Environment)
        .await
        .expect("a failed replenishment is not an error");
    assert_eq!(promoted, 0);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        config_before,
        "no candidate may be promoted into the config"
    );
}

/// Drives `top_up_with` with scripted drain results; returns the outcome,
/// the `want` of every drain call and the number of refresh calls.
async fn scripted_top_up(
    cfg: &Config,
    target: usize,
    drains: &[usize],
    refresh_result: Result<()>,
) -> (Result<usize>, Vec<usize>, usize) {
    let mut script = drains
        .iter()
        .copied()
        .collect::<std::collections::VecDeque<_>>();
    let mut asked = Vec::new();
    let mut refreshes = 0;
    let outcome = top_up_with(
        cfg,
        target,
        |want| {
            asked.push(want);
            let promoted = script.pop_front().expect("no drain left in the script");
            async move { Ok(promoted) }
        },
        || {
            refreshes += 1;
            async move { refresh_result }
        },
    )
    .await;
    (outcome, asked, refreshes)
}

fn config_with_a_source() -> Config {
    let mut cfg = Config::default();
    cfg.bridges.sources = vec![source("pool", "http://127.0.0.1:1/bridges.txt")];
    cfg
}

/// ROLLBACK THAT FAILS THIS: dropping the `promoted < target` guard refreshes
/// (a network fetch over Tor) even though the pool already covered the need.
#[tokio::test]
async fn a_pool_that_covers_the_target_never_refreshes() {
    let (outcome, asked, refreshes) =
        scripted_top_up(&config_with_a_source(), 3, &[3], Ok(())).await;
    assert_eq!(outcome.unwrap(), 3);
    assert_eq!(asked, [3]);
    assert_eq!(refreshes, 0);
}

/// ROLLBACK THAT FAILS THIS: asking the second drain for `target` instead of
/// the remaining shortfall, or not adding the first drain's promotions, breaks
/// the asked list or the total.
#[tokio::test]
async fn a_short_pool_refreshes_once_and_drains_only_the_shortfall() {
    let (outcome, asked, refreshes) =
        scripted_top_up(&config_with_a_source(), 3, &[1, 2], Ok(())).await;
    assert_eq!(outcome.unwrap(), 3);
    assert_eq!(asked, [3, 2]);
    assert_eq!(refreshes, 1);
}

/// ROLLBACK THAT FAILS THIS: dropping the sources check refreshes with
/// nothing to fetch from.
#[tokio::test]
async fn a_short_pool_without_sources_keeps_what_it_promoted() {
    let mut cfg = Config::default();
    cfg.bridges.sources.clear();
    let (outcome, asked, refreshes) = scripted_top_up(&cfg, 3, &[1], Ok(())).await;
    assert_eq!(outcome.unwrap(), 1);
    assert_eq!(asked, [3]);
    assert_eq!(refreshes, 0);
}

/// ROLLBACK THAT FAILS THIS: swallowing the refresh error drains again after
/// a failed refresh and returns Ok.
#[tokio::test]
async fn a_failed_refresh_aborts_the_top_up_before_the_second_drain() {
    let (outcome, asked, refreshes) = scripted_top_up(
        &config_with_a_source(),
        3,
        &[1],
        Err(anyhow::anyhow!("refresh failed")),
    )
    .await;
    assert!(outcome.is_err());
    assert_eq!(asked, [3]);
    assert_eq!(refreshes, 1);
}

// Not covered here, with reasons (H19.3 sub-items unreachable offline):
// - the end-to-end `config_stale` migration during a successful refresh:
//   it only runs after a fetch that returned bridges, impossible over an
//   unbootstrapped tunnel. `migrate_legacy_source` itself (URL rewrite +
//   retired drop) is covered by `fetch_merge_source_tests::
//   migration_drops_retired_sources_and_moves_legacy_ones`.
