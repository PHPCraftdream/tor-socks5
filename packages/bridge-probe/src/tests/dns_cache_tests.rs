use crate::dns::*;
use crate::*;
use bridge_line::BridgeLine;

/// The cache tests share one process-wide map, so each uses its own
/// hostname and cleans up after itself rather than flushing the lot.
#[test]
fn cached_answer_is_returned_until_it_expires() {
    let host = "cache-hit.test.invalid";
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(addrs)) => assert_eq!(addrs, vec![ip]),
        _ => panic!("a fresh answer must be served from the cache"),
    }

    forget_dns_answer(host);
    assert!(cached_doh_answer(host).is_none());
}

#[test]
fn expired_answer_is_not_served_by_the_normal_path() {
    let host = "cache-stale.test.invalid";
    // Straight into the map with an expiry already in the past — the
    // public helper clamps TTLs upwards, so it cannot express this.
    store_cached(
        host,
        CachedAnswer {
            addrs: vec!["203.0.113.8".parse().unwrap()],
            expires_at: Instant::now() - Duration::from_secs(1),
            resolved_at_unix: now_unix() - 61,
        },
    );
    assert!(cached_doh_answer(host).is_none());
    // Deliberately NOT dropped: an expired-but-recent positive answer
    // must survive for `stale_fallback_answer` to serve as a last
    // resort when every DoH provider is unreachable.
    assert!(
        doh_cache().lock().unwrap().contains_key(host),
        "an expired positive answer must stay available for the stale fallback"
    );
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_serves_a_recently_expired_positive_answer() {
    let host = "cache-stale-fallback.test.invalid";
    let ip: IpAddr = "203.0.113.20".parse().unwrap();
    store_cached(
        host,
        CachedAnswer {
            addrs: vec![ip],
            expires_at: Instant::now() - Duration::from_secs(60),
            resolved_at_unix: now_unix() - 121,
        },
    );
    assert_eq!(stale_fallback_answer(host), Some(vec![ip]));
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_refuses_an_answer_past_the_fallback_window() {
    let host = "cache-too-stale.test.invalid";
    store_cached(
        host,
        CachedAnswer {
            addrs: vec!["203.0.113.21".parse().unwrap()],
            expires_at: Instant::now() - DNS_STALE_FALLBACK_WINDOW - Duration::from_secs(1),
            resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 61,
        },
    );
    assert!(stale_fallback_answer(host).is_none());
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_refuses_a_fresh_answer() {
    // A still-valid entry must be served by `cached_doh_answer`, not by
    // the stale path -- `resolve_addrs` only calls the latter after a
    // live DoH round has already failed.
    let host = "cache-fresh-not-stale.test.invalid";
    remember_doh_answer(
        host,
        &["203.0.113.22".parse().unwrap()],
        Duration::from_secs(300),
    );
    assert!(stale_fallback_answer(host).is_none());
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_refuses_a_remembered_failure() {
    let host = "cache-negative-not-stale.test.invalid";
    remember_doh_failure(host);
    // Force it into the past so it would otherwise look "expired".
    {
        let mut cache = doh_cache().lock().unwrap();
        cache.get_mut(host).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
    }
    assert!(stale_fallback_answer(host).is_none());
    forget_dns_answer(host);
}

#[test]
fn persisted_line_round_trips() {
    let entry = PersistedAnswer {
        addrs: vec![
            "203.0.113.30".parse().unwrap(),
            "203.0.113.31".parse().unwrap(),
        ],
        resolved_at_unix: 1_700_000_000,
    };
    let line = format_persisted_line("example.test.invalid", &entry);
    let (host, parsed) = parse_persisted_line(&line).expect("line must parse back");
    assert_eq!(host, "example.test.invalid");
    assert_eq!(parsed.addrs, entry.addrs);
    assert_eq!(parsed.resolved_at_unix, entry.resolved_at_unix);
}

#[test]
fn parse_persisted_line_rejects_garbage() {
    assert!(parse_persisted_line("").is_none());
    assert!(parse_persisted_line("only-a-host").is_none());
    assert!(parse_persisted_line("host\t\tnotanumber").is_none());
    assert!(parse_persisted_line("host\tnotanip\t123").is_none());
}

#[tokio::test]
async fn save_and_load_persisted_cache_round_trips_through_disk_fallback() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "cache-disk-roundtrip.test.invalid";
    let ip: IpAddr = "203.0.113.40".parse().unwrap();
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!("bridge-probe-dns-cache-test-{}", now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    forget_dns_answer(host); // wipe the in-memory entry entirely

    load_persisted_dns_cache(&path);
    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn disk_fallback_refuses_an_answer_past_the_fallback_window() {
    // Sync test: no ambient runtime, so acquire the async store lock
    // through a throwaway one (see DNS_GLOBAL_STORE_LOCK in tests/mod.rs).
    let _dns_serial = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime builds")
        .block_on(super::DNS_GLOBAL_STORE_LOCK.lock());
    let host = "cache-disk-too-stale.test.invalid";
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec!["203.0.113.41".parse().unwrap()],
                resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
            },
        );
    }
    assert!(disk_fallback_answer(host).is_none());
}

#[test]
fn load_persisted_dns_cache_is_a_no_op_for_a_missing_file() {
    // Must not panic -- a first run, or one predating this feature.
    load_persisted_dns_cache(std::path::Path::new("/nonexistent/does-not-exist.txt"));
}

#[test]
fn dns_hint_line_round_trips() {
    let hint = DnsHint {
        host: "bridge.example.test".to_owned(),
        addrs: vec![
            "198.51.100.5".parse().unwrap(),
            "198.51.100.6".parse().unwrap(),
        ],
        resolved_at_unix: 1_700_000_500,
    };
    let line = format_dns_hint_line(&hint);
    assert!(line.starts_with(DNS_HINT_PREFIX));
    assert_eq!(parse_dns_hint_line(&line), Some(hint));
}

#[test]
fn parse_dns_hint_line_rejects_non_hint_lines() {
    assert!(parse_dns_hint_line("obfs4 1.2.3.4:443 ABCDEF cert=x").is_none());
    assert!(parse_dns_hint_line("# just a comment").is_none());
    assert!(parse_dns_hint_line("").is_none());
    assert!(parse_dns_hint_line("# xorbot:dns onlyhost").is_none());
    assert!(parse_dns_hint_line("# xorbot:dns host notanip 123").is_none());
}

#[test]
fn dns_hostname_of_is_none_for_ip_only_bridges() {
    let obfs4: BridgeLine =
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    assert_eq!(dns_hostname_of(&obfs4), None);

    let webtunnel_addr: BridgeLine =
        "webtunnel 192.0.2.2:1 0123456789ABCDEF0123456789ABCDEF01234567 addr=192.0.2.9:443 url=https://example.com/x"
            .parse()
            .unwrap();
    assert_eq!(dns_hostname_of(&webtunnel_addr), None);
}

#[test]
fn dns_hostname_of_finds_the_webtunnel_url_host() {
    let webtunnel: BridgeLine =
        "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://fronting.example.test/x"
            .parse()
            .unwrap();
    assert_eq!(
        dns_hostname_of(&webtunnel),
        Some("fronting.example.test".to_owned())
    );
}

#[test]
fn best_known_answer_prefers_live_cache_over_disk() {
    // Sync test: acquires the store lock via a throwaway runtime (see
    // DNS_GLOBAL_STORE_LOCK in tests/mod.rs).
    let _dns_serial = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime builds")
        .block_on(super::DNS_GLOBAL_STORE_LOCK.lock());
    let host = "best-answer-live.test.invalid";
    let live_ip: IpAddr = "203.0.113.50".parse().unwrap();
    remember_doh_answer(host, &[live_ip], Duration::from_secs(300));
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec!["203.0.113.51".parse().unwrap()],
                resolved_at_unix: now_unix(),
            },
        );
    }
    let hint = best_known_answer(host).expect("must find an answer");
    assert_eq!(hint.addrs, vec![live_ip]);
    forget_dns_answer(host);
}

#[test]
fn best_known_answer_falls_back_to_disk_when_live_cache_is_empty() {
    // Sync test: acquires the store lock via a throwaway runtime (see
    // DNS_GLOBAL_STORE_LOCK in tests/mod.rs).
    let _dns_serial = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime builds")
        .block_on(super::DNS_GLOBAL_STORE_LOCK.lock());
    let host = "best-answer-disk.test.invalid";
    let ip: IpAddr = "203.0.113.52".parse().unwrap();
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix(),
            },
        );
    }
    let hint = best_known_answer(host).expect("must find an answer");
    assert_eq!(hint.addrs, vec![ip]);
}

#[test]
fn best_known_answer_is_none_when_nothing_is_known() {
    assert!(best_known_answer("never-seen.test.invalid").is_none());
}

#[test]
fn seed_disk_fallback_respects_last_write_wins() {
    // Sync test: acquires the store lock via a throwaway runtime (see
    // DNS_GLOBAL_STORE_LOCK in tests/mod.rs).
    let _dns_serial = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime builds")
        .block_on(super::DNS_GLOBAL_STORE_LOCK.lock());
    let host = "seed-lww.test.invalid";
    let older: IpAddr = "203.0.113.60".parse().unwrap();
    let newer: IpAddr = "203.0.113.61".parse().unwrap();
    seed_disk_fallback(&[DnsHint {
        host: host.to_owned(),
        addrs: vec![newer],
        resolved_at_unix: 2_000_000_000,
    }]);
    // An older hint must not overwrite the newer one already seeded.
    seed_disk_fallback(&[DnsHint {
        host: host.to_owned(),
        addrs: vec![older],
        resolved_at_unix: 1_000_000_000,
    }]);
    assert_eq!(
        disk_fallback_store()
            .lock()
            .unwrap()
            .get(host)
            .unwrap()
            .addrs,
        vec![newer]
    );
}

#[test]
fn a_failed_resolution_is_remembered_briefly() {
    let host = "cache-negative.test.invalid";
    remember_doh_failure(host);
    assert!(matches!(
        cached_doh_answer(host),
        Some(CacheHit::Unresolvable)
    ));
    forget_dns_answer(host);
}

#[test]
fn ttl_is_clamped_into_the_useful_range() {
    let host = "cache-ttl.test.invalid";
    let ip: IpAddr = "203.0.113.9".parse().unwrap();

    // A CDN's 20-second TTL must not send us back to the providers on the
    // next round.
    remember_doh_answer(host, &[ip], Duration::from_secs(20));
    let floor = doh_cache().lock().unwrap()[host].expires_at;
    assert!(floor >= Instant::now() + DNS_MIN_TTL - Duration::from_secs(1));

    // A record claiming a day must not outlive the bridge moving.
    remember_doh_answer(host, &[ip], Duration::from_secs(86_400));
    let ceiling = doh_cache().lock().unwrap()[host].expires_at;
    assert!(ceiling <= Instant::now() + DNS_MAX_TTL);

    forget_dns_answer(host);
}
