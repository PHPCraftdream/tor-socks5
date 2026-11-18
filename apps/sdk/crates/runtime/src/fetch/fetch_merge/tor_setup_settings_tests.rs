//! H19.3 coverage for the `build_tor_settings` chain WITHOUT a pre-proxy
//! (the production fallback chain): configured bridge lines → retire /
//! circuit-fail filter → preferred-transport pool → startup probe → ranking
//! (store health tiers) with the [`MAX_ACTIVE_BRIDGES`] cap → `Settings`.
//!
//! All probes are stubbed via the `SDK14_PT_OBSERVER` task-local seam
//! (`probe_measured` short-circuits to "everything alive" when the observer
//! is present), so every test here is offline-deterministic and states which
//! production rollback would break it.
//!
//! NOTE on placement: this file lives under `fetch/fetch_merge/` only
//! because both `src/` and `src/tor/` are at their 7-entry directory cap
//! (see the declaration in `lib.rs`); it exclusively tests
//! `tor_setup::build_tor_settings`.

use crate::config::Config;
use crate::tor_setup::{build_tor_settings, MAX_ACTIVE_BRIDGES};
use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use std::path::Path;
use time::OffsetDateTime;

/// Run `build_tor_settings` with the probe stub active: every bridge
/// "answers" its TCP probe with a 1 ms latency, so the whole fallback chain
/// can be driven without any network. The channel absorbs the PT-binary
/// resolution report the seam emits when any bridge needs a transport.
async fn build_settings_with_stubbed_probes(
    cfg: &Config,
    config_path: &Path,
) -> anyhow::Result<arti_wrapper::Settings> {
    let (tx, _rx) = tokio::sync::mpsc::channel::<(&'static str, std::path::PathBuf)>(16);
    crate::pt::SDK14_PT_OBSERVER
        .scope(
            ("tor_setup_settings_tests", tx),
            build_tor_settings(cfg, config_path),
        )
        .await
}

/// Plain (transport-less) bridge line on a distinct address (the identity
/// that matters for the store and ranking is the full address+fingerprint
/// pair; the fingerprint is a fixed syntactically valid placeholder).
fn plain_line(last_octet: u32) -> BridgeLine {
    format!("10.0.0.{last_octet}:443 1111111111111111111111111111111111111111")
        .parse()
        .expect("valid plain bridge line")
}

fn obfs4_line(last_octet: u32) -> BridgeLine {
    format!(
        "obfs4 10.0.1.{last_octet}:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0"
    )
    .parse()
    .expect("valid obfs4 bridge line")
}

fn webtunnel_line(last_octet: u32) -> BridgeLine {
    format!(
        "webtunnel 10.0.2.{last_octet}:443 3333333333333333333333333333333333333333 url=https://example.com/x"
    )
    .parse()
    .expect("valid webtunnel bridge line")
}

/// Write the on-disk health store next to `config_path`, seeded by `seed`.
fn seed_store(config_path: &Path, seed: impl FnOnce(&mut BridgeStore)) {
    let store_path = BridgeStore::resolve_path(config_path);
    let mut store = BridgeStore::load(store_path.clone()).expect("load (possibly empty) store");
    seed(&mut store);
    store.save().expect("save seeded store");
}

/// Credit one bridge with a successful probe round in the store.
fn note_alive(store: &mut BridgeStore, bridge: &BridgeLine, now: OffsetDateTime) {
    store.note_probe_round(
        std::slice::from_ref(bridge),
        &[(bridge.clone(), std::time::Duration::from_millis(1))],
        now,
        std::time::Duration::ZERO,
        u32::MAX,
        u32::MAX,
    );
}

/// Canonical comparable form for set comparison (`BridgeLine` is not `Ord`).
fn sorted_strings(bridges: &[BridgeLine]) -> Vec<String> {
    let mut strings: Vec<String> = bridges.iter().map(BridgeLine::to_string).collect();
    strings.sort();
    strings
}

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// H19.3 leg "active slice + ranking": with no transport preference, the
/// produced `Settings.bridges` must be exactly the configured (non-retired)
/// bridges, ordered by the store's health tiers — circuit-verified above
/// channel-proven above merely TCP-probed — and a retired bridge must be
/// excluded outright.
///
/// ROLLBACK THAT FAILS THIS: dropping `update_health_and_prune`'s
/// `retain_and_rank_alive` re-sort (bridges fall back to probe order) or
/// dropping the `store.is_retired` pre-probe filter (the retired bridge is
/// probed again and re-enters the list) — either regression changes the
/// asserted contents or order.
#[tokio::test]
async fn settings_rank_configured_bridges_by_store_health_and_drop_retired() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("proxy.ktav");
    let a = plain_line(1);
    let b = plain_line(2);
    let c = plain_line(3);
    let retired = plain_line(4);
    let mut cfg = Config::default();
    cfg.bridges.lines = [a.clone(), b.clone(), c.clone(), retired.clone()]
        .iter()
        .map(BridgeLine::to_string)
        .collect();
    cfg.bridges.use_seeds = false;
    cfg.write(&config_path).expect("write config");

    let now = now_utc();
    seed_store(&config_path, |store| {
        // a: end-to-end verified (top tier) and channel-proven.
        note_alive(store, &a, now);
        store.note_channel_success_at(&a, now);
        store.note_circuit_verified_at(&a, now);
        // b: channel-proven only (middle tier).
        note_alive(store, &b, now);
        store.note_channel_success_at(&b, now);
        // c: TCP-proven only (bottom tier).
        note_alive(store, &c, now);
        // retired: a permanent (stale-identity) failure — never re-probed.
        store.note_permanent_failure_at(&retired, now);
    });

    let settings = build_settings_with_stubbed_probes(&cfg, &config_path)
        .await
        .expect("build settings");
    assert_eq!(settings.bridges, vec![a, b, c]);
    assert!(!settings.bridges.contains(&retired));
}

/// H19.3 leg "over-limit active list": a configured list larger than
/// [`MAX_ACTIVE_BRIDGES`] must be capped to exactly that many bridges, taken
/// from the front of the configured list when the store has no history
/// (documented fresh-install fallback), and every survivor must end up in
/// the produced `Settings.bridges`.
///
/// ROLLBACK THAT FAILS THIS: removing the `MAX_ACTIVE_BRIDGES` cap in
/// `select_active_probe_bridges` / `update_health_and_prune` lets all 35
/// configured bridges through and `settings.bridges` grows past the cap.
#[tokio::test]
async fn settings_cap_over_limit_config_to_max_active_bridges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("proxy.ktav");
    let configured: Vec<BridgeLine> = (0..(MAX_ACTIVE_BRIDGES + 5))
        .map(|i| plain_line(i as u32 % 256))
        .collect();
    let mut cfg = Config::default();
    cfg.bridges.lines = configured.iter().map(BridgeLine::to_string).collect();
    cfg.bridges.use_seeds = false;
    cfg.write(&config_path).expect("write config");

    let settings = build_settings_with_stubbed_probes(&cfg, &config_path)
        .await
        .expect("build settings");
    assert_eq!(settings.bridges.len(), MAX_ACTIVE_BRIDGES);
    // No store history: the active slice is the head of the configured list
    // (fresh-install fallback). The final ranking breaks rank ties by store
    // identity order, so compare as sets.
    let expected: Vec<BridgeLine> = configured
        .iter()
        .take(MAX_ACTIVE_BRIDGES)
        .cloned()
        .collect();
    let got = sorted_strings(&settings.bridges);
    let mut expected: Vec<String> = expected.iter().map(BridgeLine::to_string).collect();
    expected.sort();
    assert_eq!(got, expected);
    // The tail beyond the cap is gone.
    assert_eq!(settings.bridges.len(), configured.len() - 5);
}

/// H19.3 leg "`.seeds` fallback file": an empty config with `use_seeds`
/// enabled and a `*.seeds` file next to it must bootstrap exactly on the
/// seed lines (the chicken-and-egg fallback probed via `SetupSeedLoad`).
///
/// ROLLBACK THAT FAILS THIS: dropping the seeds branch in
/// `build_tor_settings_inner` (or its `use_seeds` gate) leaves
/// `Settings.bridges` empty and the call errors with "no reachable bridge".
#[tokio::test]
async fn settings_fall_back_to_seed_file_when_configured_list_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("proxy.ktav");
    let seed_a = plain_line(1);
    let seed_b = plain_line(2);
    std::fs::write(
        dir.path().join("proxy.seeds"),
        format!("# seeded bootstrap bridges\n{}\n{}\n", seed_a, seed_b),
    )
    .expect("write seeds file");
    let mut cfg = Config::default();
    cfg.bridges.lines.clear();
    cfg.bridges.use_seeds = true;
    cfg.write(&config_path).expect("write config");

    let settings = build_settings_with_stubbed_probes(&cfg, &config_path)
        .await
        .expect("build settings");
    assert_eq!(settings.bridges, vec![seed_a, seed_b]);
    // Arti state stays app-local, next to the config file.
    assert_eq!(settings.state_dir, Some(dir.path().join("arti-data")));
}

/// H19.3 leg "preferred pool → obfs4": a webtunnel transport preference
/// whose matching bridges are all retired (stale identities) must fall back
/// to the configured obfs4 bridges only — never to the (healthy) other
/// transports in the config — and activate the in-process PT binary.
///
/// ROLLBACK THAT FAILS THIS: `preferred_transport_bridges`' unmatched-
/// preference fallback (returning the full pool for a dead webtunnel slice)
/// would put the non-obfs4 bridge back into `Settings.bridges`.
#[tokio::test]
async fn settings_dead_webtunnel_preference_falls_back_to_obfs4_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("proxy.ktav");
    let dead_wt_1 = webtunnel_line(1);
    let dead_wt_2 = webtunnel_line(2);
    let obfs4_a = obfs4_line(1);
    let obfs4_b = obfs4_line(2);
    let other = plain_line(9);
    let mut cfg = Config::default();
    cfg.bridges.transport = "webtunnel".to_owned();
    cfg.bridges.lines = [
        dead_wt_1.clone(),
        dead_wt_2.clone(),
        obfs4_a.clone(),
        obfs4_b.clone(),
        other.clone(),
    ]
    .iter()
    .map(BridgeLine::to_string)
    .collect();
    cfg.bridges.use_seeds = false;
    cfg.write(&config_path).expect("write config");

    let now = now_utc();
    seed_store(&config_path, |store| {
        // Both webtunnel bridges carry stale identities: permanently failed
        // at the circuit layer, so the pre-probe retire filter drops them.
        store.note_permanent_failure_at(&dead_wt_1, now);
        store.note_permanent_failure_at(&dead_wt_2, now);
    });

    let settings = build_settings_with_stubbed_probes(&cfg, &config_path)
        .await
        .expect("build settings");
    let got = sorted_strings(&settings.bridges);
    let mut want = vec![obfs4_a.to_string(), obfs4_b.to_string()];
    want.sort();
    assert_eq!(got, want, "only the configured obfs4 bridges survive");
    assert!(settings.bridges.iter().all(|b| b.transport.is_some()));
    // A transport in the list points arti's PT manager at our own binary.
    assert_eq!(settings.pt_binary, Some(std::env::current_exe().unwrap()));
}

/// Documented negative result (H19.3): `build_tor_settings` has NO candidate
/// pool leg. The candidate pool (`<stem>.candidates.log`) is consumed by
/// `fetch_merge::drain_pool`, which promotes candidates into the config
/// *lines*; `build_tor_settings` then reads those lines like any other. This
/// test pins that contract: a seeded pool next to the config does not change
/// the produced `Settings` at all (the settings still follow the config
/// lines), and the pool file is left untouched.
///
/// ROLLBACK THAT FAILS THIS: someone adding a pool read into
/// `build_tor_settings_inner` would make the pooled candidate appear in
/// `Settings.bridges` and this test fails.
#[tokio::test]
async fn settings_ignore_the_candidate_pool_file() {
    use crate::candidate_pool::CandidatePool;
    use std::collections::HashSet;

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("proxy.ktav");
    let configured = plain_line(1);
    let pooled = plain_line(7);
    let mut cfg = Config::default();
    cfg.bridges.lines = vec![configured.to_string()];
    cfg.bridges.use_seeds = false;
    cfg.write(&config_path).expect("write config");
    let pool_path = CandidatePool::resolve_path(&config_path);
    let mut pool = CandidatePool::load(pool_path.clone()).expect("load empty pool");
    assert_eq!(pool.merge([pooled.clone()], &HashSet::new()), 1);
    pool.save().expect("seed pool");

    let settings = build_settings_with_stubbed_probes(&cfg, &config_path)
        .await
        .expect("build settings");
    assert_eq!(settings.bridges, vec![configured]);
    let after = CandidatePool::load(pool_path).expect("reload pool");
    assert_eq!(
        after.len(),
        1,
        "pool must not be consumed by settings build"
    );
}

// Not covered here, with reasons (H19.3 sub-items reachable only with
// selective probe failure, which no seam provides offline):
// - the post-probe obfs4 fallback branch ("no reachable WebTunnel bridges;
//   probing obfs4 fallback"): needs the preferred-transport probes to fail
//   while obfs4 probes succeed. The probe stub is all-or-nothing, so the
//   covered `settings_dead_webtunnel_preference_falls_back_to_obfs4_only`
//   pins the reachable variant of the same leg (retire-filter instead of
//   probe failure).
// - the `.seeds` fallback for a NON-empty config where every configured
//   bridge fails its probe: same all-or-nothing probe stub limitation; the
//   covered seeds test pins the leg itself (empty config).
// - the preferred-pool leg ("bridges come from the candidate pool"): the
//   production chain has no pool read — pinned explicitly by
//   `settings_ignore_the_candidate_pool_file`.
