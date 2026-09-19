//! Demonstrates the `proxy_config` crate: building a `Config` from defaults,
//! writing it to a Ktav file atomically with `Config::write`, loading it back
//! via `Config::load_with_override` (the CLI override wins), and walking the
//! main sections, including bridge-line parsing with duplicate removal.

use proxy_config::{BridgesConfig, Config, Loaded};

fn main() -> anyhow::Result<()> {
    let cfg = Config {
        listen: "127.0.0.1:9050".to_string(),
        bridges: BridgesConfig {
            lines: vec![
                "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
                    .to_string(),
                "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WWW iat-mode=0"
                    .to_string(),
                // Exact repeat of the first line: `parsed()` must drop the duplicate.
                "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
                    .to_string(),
            ],
            ..Default::default()
        },
        ..Default::default()
    };

    let path =
        std::env::temp_dir().join(format!("proxy-config-example-{}.ktav", std::process::id()));
    cfg.write(&path)?;
    println!("config written to {}", path.display());

    // The explicit path (as a CLI flag would provide) overrides the default
    // config location.
    let loaded = Config::load_with_override(Some(&path))?;
    match &loaded {
        Loaded::FromFile { path, .. } => println!("loaded from file: {}", path.display()),
        Loaded::Defaults(_) => println!("loaded from defaults (unexpected here)"),
    }
    let cfg = loaded.into_config();

    println!("listen: {}", cfg.listen);
    println!(
        "log: filter {:?}, output {:?}",
        cfg.log.to_filter(),
        cfg.log.output
    );
    println!(
        "dns: doh_enabled {}, system_fallback {}, policy {:?}",
        cfg.dns.doh_enabled,
        cfg.dns.system_fallback,
        cfg.dns.resolver_policy()
    );

    println!("bridges: {} raw lines", cfg.bridges.lines.len());
    let parsed = cfg.bridges.parsed()?;
    println!(
        "bridges parsed: {} kept (expected 2), {} duplicates (expected 1), {} rejected",
        parsed.bridges.len(),
        parsed.duplicates,
        parsed.rejected
    );
    println!(
        "dns hints: {} | first bridge addr: {}",
        parsed.dns_hints.len(),
        parsed.bridges[0].addr
    );

    println!(
        "watchdog: enabled {}, stale_after {}s, rebuild_cooldown {}s",
        cfg.watchdog.enabled, cfg.watchdog.stale_after_secs, cfg.watchdog.rebuild_cooldown_secs
    );
    println!(
        "warm_pool: enabled {}, pool_size {} | conn_health: enabled {}, interval {}s",
        cfg.warm_pool.enabled,
        cfg.warm_pool.pool_size,
        cfg.conn_health.enabled,
        cfg.conn_health.interval_secs
    );

    // UpstreamConfig's Debug impl redacts the proxy password.
    println!(
        "upstream: enabled {}, address {:?}",
        cfg.upstream.enabled, cfg.upstream.address
    );
    println!(
        "auth: enabled {}, users_file {:?}",
        cfg.auth.enabled, cfg.auth.users_file
    );
    println!("security: block_onion {}", cfg.security.block_onion);
    println!(
        "default bridge sources: {}",
        proxy_config::default_bridge_sources().len()
    );

    std::fs::remove_file(&path)?;
    Ok(())
}
