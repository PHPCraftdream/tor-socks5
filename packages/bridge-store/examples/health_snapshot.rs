//! Demonstrates `bridge_store::BridgeStore` health tracking: recording probe
//! rounds with `note_probe_round`, reading per-bridge `HealthSnapshot` values,
//! atomically saving with `save`, and reloading the health state after a
//! simulated restart. The scratch store directory is removed at the end.

use std::path::PathBuf;
use std::time::Duration;

use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use time::OffsetDateTime;

fn main() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("bridge-store-example-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path: PathBuf = dir.join("bridges.log");

    // A missing file loads as an empty store. In a real deployment this file
    // persists across runs, so the counters below survive restarts.
    let mut store = BridgeStore::load(path.clone())?;
    println!(
        "loaded store at {}: {} bridges",
        path.display(),
        store.len()
    );

    let line_a: BridgeLine =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
            .parse()
            .expect("valid bridge line a");
    let line_b: BridgeLine =
        "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WWW iat-mode=0"
            .parse()
            .expect("valid bridge line b");

    // Round 1: both bridges were probed, only `a` answered. A bridge is pruned
    // once its consecutive fails reach `max_fails`; failure bumps are
    // rate-limited to once per `fail_window`, so expect zero prunes here.
    let now = OffsetDateTime::now_utc();
    let pruned = store.note_probe_round(
        &[line_a.clone(), line_b.clone()],
        &[(line_a.clone(), Duration::from_millis(234))],
        now,
        Duration::from_secs(3600),
        24,
        5,
    );
    println!("round 1: pruned {} bridges (expected 0)", pruned.len());

    // Round 2: only `b` was probed and nothing answered, so its consecutive
    // TCP-fail counter climbs from 0 to 1.
    let pruned = store.note_probe_round(
        std::slice::from_ref(&line_b),
        &[],
        OffsetDateTime::now_utc(),
        Duration::from_secs(3600),
        24,
        5,
    );
    println!("round 2: pruned {} bridges", pruned.len());
    println!(
        "health snapshot for b: {:?}",
        store.health_snapshot(&line_b)
    );

    // `save` publishes atomically (temp file + rename).
    store.save()?;
    println!("store saved to {}", store.path().display());

    // Reloading from disk shows health observations survive a restart.
    let reloaded = BridgeStore::load(path)?;
    println!("reloaded store: {} bridges (expected 2)", reloaded.len());
    for stats in reloaded.transport_summary() {
        println!(
            "  {}: {} known, {} alive, {} channel-proven, {} retired",
            stats.transport, stats.known, stats.alive, stats.channel_proven, stats.retired
        );
    }
    let healthiest = reloaded.healthiest_bridges(10);
    println!("healthiest bridges: {}", healthiest.len());
    if let Some(first) = healthiest.first() {
        println!("  first: {}", first);
    }

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
