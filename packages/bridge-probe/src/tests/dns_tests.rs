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

#[tokio::test]
async fn save_preserves_an_unexpired_disk_fallback_entry() {
    let host = "save-keeps-disk.test.invalid";
    let ip: IpAddr = "203.0.113.70".parse().unwrap();
    let stamp = now_unix() - 3600;
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: stamp,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-keeps-disk-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&stamp.to_string()),
        "saved file must carry the ORIGINAL stamp, got: {file_text}"
    );

    // Simulate the next cold start: wipe this test's own key (not the
    // whole store -- it's process-wide and shared by other tests running
    // concurrently, so a blanket `clear()` here would race their inserts),
    // then reload.
    disk_fallback_store().lock().unwrap().remove(host);
    forget_dns_answer(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));
    let reloaded_stamp = {
        let store = disk_fallback_store().lock().unwrap();
        let entry = store.get(host).expect("host must survive save/wipe/load");
        entry.resolved_at_unix
    };
    assert_eq!(
        reloaded_stamp, stamp,
        "save must not refresh the persisted stamp"
    );

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[tokio::test]
async fn save_drops_a_genuinely_expired_disk_fallback_entry() {
    let host = "save-drops-expired.test.invalid";
    let ip: IpAddr = "203.0.113.71".parse().unwrap();
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-drops-expired-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !file_text.contains(host),
        "expired entry must not be written, got: {file_text}"
    );

    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), None);
    assert!(!disk_fallback_store().lock().unwrap().contains_key(host));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[tokio::test]
async fn save_prefers_the_live_answer_for_a_host() {
    let host = "save-live-wins.test.invalid";
    let live_ip: IpAddr = "203.0.113.72".parse().unwrap();
    let disk_ip: IpAddr = "203.0.113.73".parse().unwrap();
    remember_doh_answer(host, &[live_ip], Duration::from_secs(300));
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![disk_ip],
                resolved_at_unix: now_unix() - 3600,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-live-wins-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&live_ip.to_string()),
        "live answer must be written, got: {file_text}"
    );
    assert!(
        !file_text.contains(&disk_ip.to_string()),
        "persisted answer must be superseded, got: {file_text}"
    );

    forget_dns_answer(host);
    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![live_ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[tokio::test]
async fn save_keeps_the_fallback_when_the_live_cache_only_remembers_a_failure() {
    let host = "save-failure-keeps-disk.test.invalid";
    let ip: IpAddr = "203.0.113.74".parse().unwrap();
    remember_doh_failure(host);
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix() - 3600,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-failure-keeps-disk-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&ip.to_string()),
        "a remembered failure must not displace the persisted fallback, got: {file_text}"
    );

    forget_dns_answer(host);
    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

/// TS5-04 regression: a resident live answer that expired beyond the
/// stale-fallback window must not be exported by a periodic save. Under the
/// old filter (`!addrs.is_empty()` only) it was written with
/// `resolved_at_unix = now`, so the next cold start accepted a day-stale
/// address as freshly resolved.
#[tokio::test]
async fn save_drops_a_resident_live_answer_past_the_stale_window() {
    let host = "save-drops-stale-live.test.invalid";
    let ip: IpAddr = "203.0.113.80".parse().unwrap();
    // Straight into the map with an expiry past the stale-fallback window --
    // `remember_doh_answer` clamps TTLs, so it cannot express this. The
    // stamp is consistent with that expiry: the answer was resolved even
    // earlier than it expired.
    store_cached(
        host,
        CachedAnswer {
            addrs: vec![ip],
            expires_at: Instant::now() - DNS_STALE_FALLBACK_WINDOW - Duration::from_secs(1),
            resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 61,
        },
    );
    let dir = std::env::temp_dir().join(format!("save-drops-stale-live-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !file_text.contains(host),
        "a resident answer past the stale-fallback window must not be \
         persisted as freshly resolved, got: {file_text}"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TS5-04 regression, priority half: the same unusable live answer must not
/// win the save's live-over-disk priority check either -- a valid, fresh
/// disk entry for the same host survives with its ORIGINAL stamp instead of
/// being dropped in favour of a day-stale resident answer.
#[tokio::test]
async fn save_keeps_a_valid_disk_answer_when_the_live_answer_is_past_the_stale_window() {
    let host = "save-disk-beats-stale-live.test.invalid";
    let stale_live_ip: IpAddr = "203.0.113.81".parse().unwrap();
    let disk_ip: IpAddr = "203.0.113.82".parse().unwrap();
    let disk_stamp = now_unix() - 3600;
    store_cached(
        host,
        CachedAnswer {
            addrs: vec![stale_live_ip],
            expires_at: Instant::now() - DNS_STALE_FALLBACK_WINDOW - Duration::from_secs(1),
            resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 61,
        },
    );
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![disk_ip],
                resolved_at_unix: disk_stamp,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "save-disk-beats-stale-live-{}-{}",
        host,
        now_unix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !file_text.contains(&stale_live_ip.to_string()),
        "the unusable live answer must not be persisted, got: {file_text}"
    );
    assert!(
        file_text.contains(&disk_ip.to_string()),
        "the valid disk answer must survive the stale live one, got: {file_text}"
    );
    assert!(
        file_text.contains(&disk_stamp.to_string()),
        "the disk answer must keep its ORIGINAL stamp, got: {file_text}"
    );

    // Simulate the next cold start: wipe only this test's own keys (the
    // stores are process-wide and shared by other tests running
    // concurrently), then reload.
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![disk_ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

/// A blocked save must leave the executor and cache available.
#[tokio::test]
async fn save_persisted_dns_cache_does_not_block_the_async_worker() {
    let host = "save-off-worker.test.invalid";
    let ip: IpAddr = "203.0.113.83".parse().unwrap();
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!("save-off-worker-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    let executor_thread = std::thread::current().id();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let save = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                assert_ne!(std::thread::current().id(), executor_thread);
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)
            })
            .await
        })
    };

    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save reaches its blocking phase")
        .expect("writer signals entry");
    let lookup = tokio::spawn(async move { cached_doh_answer(host) });
    let hit = tokio::time::timeout(Duration::from_secs(10), lookup)
        .await
        .expect("cache lookup progresses during save")
        .expect("lookup task joins");
    assert!(matches!(hit, Some(CacheHit::Addrs(addrs)) if addrs == vec![ip]));
    assert!(!save.is_finished(), "writer still awaits release");
    release_tx.send(()).expect("release this writer");
    tokio::time::timeout(Duration::from_secs(10), save)
        .await
        .expect("released save completes")
        .expect("save task joins")
        .expect("save succeeds");

    // Semantics unchanged: the held save still landed everything it should.
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(host),
        "the saved file must contain the host, got: {file_text}"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A save whose job is still mid-flight when a newer save completes must
/// skip publication entirely: the newer snapshot stays on disk, nothing is
/// interleaved, and no temp file is left behind.
#[tokio::test]
async fn superseded_save_must_not_publish_stale_snapshot() {
    let host_b = "superseded-b.test.invalid";
    let host_extra = "superseded-extra.test.invalid";
    let ip1: IpAddr = "203.0.113.91".parse().unwrap();
    let extra_ip: IpAddr = "203.0.113.92".parse().unwrap();
    let ip2: IpAddr = "203.0.113.93".parse().unwrap();

    // A's snapshot: long (two entries), seeded with an older stamp.
    remember_doh_answer(host_b, &[ip1], Duration::from_secs(3000));
    remember_doh_answer(host_extra, &[extra_ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "superseded-save-{}-{}",
        std::process::id(),
        now_unix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Save A: held mid-write by the writer until we release it.
    let executor_thread = std::thread::current().id();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let save_a = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                assert_ne!(std::thread::current().id(), executor_thread);
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)?;
                Ok(())
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save A reaches its blocking phase")
        .expect("writer A signals entry");

    // Now the state changes under A: B's snapshot is short and different.
    forget_dns_answer(host_extra);
    remember_doh_answer(host_b, &[ip2], Duration::from_secs(3000));
    save_persisted_dns_cache(&path)
        .await
        .expect("save B must succeed");

    // Release A: it must detect it was superseded and skip publication.
    release_tx.send(()).expect("release writer A");
    let result_a = tokio::time::timeout(Duration::from_secs(10), save_a)
        .await
        .expect("released save A completes")
        .expect("save A task joins");
    assert!(
        result_a.is_ok(),
        "a superseded save skips publication and returns Ok, got: {result_a:?}"
    );

    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&format!("{host_b}	{ip2}")),
        "the newer snapshot must be published, got: {file_text}"
    );
    assert!(
        !file_text.contains(&ip1.to_string()),
        "the stale IP must not survive, got: {file_text}"
    );
    assert!(
        !file_text.contains(host_extra),
        "the dropped host must not survive, got: {file_text}"
    );
    // Other tests running in parallel share the process-wide disk fallback
    // store, so foreign hosts may legitimately appear in the snapshot; every
    // line for OUR hosts must parse (no mixture/tail residue).
    let our_hosts = [host_b, host_extra];
    for line in file_text.lines() {
        let foreign = !our_hosts.iter().any(|host| line.starts_with(host));
        assert!(
            foreign || parse_persisted_line(line).is_some(),
            "every own line must parse, got: {line}"
        );
    }
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "superseded saves must remove their temp files, found: {leftovers:?}"
    );

    forget_dns_answer(host_b);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cancelled caller cannot stop its already-dispatched blocking job; the
/// generation check must keep that detached job from clobbering the newer
/// snapshot a subsequent save published.
#[tokio::test]
async fn cancelled_caller_leaves_latest_snapshot_intact() {
    let host_b = "cancel-b.test.invalid";
    let host_extra = "cancel-extra.test.invalid";
    let ip1: IpAddr = "203.0.113.94".parse().unwrap();
    let extra_ip: IpAddr = "203.0.113.95".parse().unwrap();
    let ip2: IpAddr = "203.0.113.96".parse().unwrap();

    remember_doh_answer(host_b, &[ip1], Duration::from_secs(3000));
    remember_doh_answer(host_extra, &[extra_ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "cancelled-save-{}-{}",
        std::process::id(),
        now_unix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Save A: held mid-write, and its caller is aborted while it waits.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (written_tx, written_rx) = tokio::sync::oneshot::channel();
    let save_a = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)?;
                let _ = written_tx.send(());
                Ok(())
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save A reaches its blocking phase")
        .expect("writer A signals entry");
    save_a.abort(); // caller future cancelled while job A runs detached

    // B wins the race and publishes the fresh, short snapshot.
    forget_dns_answer(host_extra);
    remember_doh_answer(host_b, &[ip2], Duration::from_secs(3000));
    save_persisted_dns_cache(&path)
        .await
        .expect("save B must succeed");

    // Release A: its job still finishes the temp write (the point of the
    // test), then must skip publication.
    release_tx.send(()).expect("release writer A");
    tokio::time::timeout(Duration::from_secs(10), written_rx)
        .await
        .expect("detached job A resumes after release")
        .expect("writer A signals the temp write");

    let file_text = std::fs::read_to_string(&path).unwrap();
    // Other tests running in parallel share the process-wide disk fallback
    // store, so foreign hosts may legitimately appear; OUR host must appear
    // exactly once, fully parsed, with nothing stale alongside it.
    for line in file_text.lines() {
        assert!(
            !line.starts_with(host_b) || parse_persisted_line(line).is_some(),
            "every own line must parse, got: {line}"
        );
    }
    assert_eq!(
        file_text
            .lines()
            .filter(|line| line.starts_with(host_b))
            .count(),
        1,
        "exactly B's snapshot line must survive for the host, got: {file_text}"
    );
    assert!(
        file_text.contains(&format!("{host_b}	{ip2}")),
        "the newer snapshot must be published, got: {file_text}"
    );
    assert!(
        !file_text.contains(&ip1.to_string()) && !file_text.contains(host_extra),
        "the stale snapshot must not survive, got: {file_text}"
    );
    forget_dns_answer(host_b);
    forget_dns_answer(host_extra);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_dns_hint_line_rejects_future_timestamps() {
    let host = "hint-future.test.invalid";
    let ip: IpAddr = "203.0.113.75".parse().unwrap();
    let make_line = |stamp: u64| {
        format_dns_hint_line(&DnsHint {
            host: host.to_owned(),
            addrs: vec![ip],
            resolved_at_unix: stamp,
        })
    };
    assert!(parse_dns_hint_line(&make_line(now_unix() + 10 * 24 * 60 * 60)).is_none());
    assert!(parse_dns_hint_line(&make_line(u64::MAX)).is_none());
    // Ordinary clock skew is not an attack: still accepted.
    assert_eq!(
        parse_dns_hint_line(&make_line(now_unix() + 30))
            .expect("modest skew must be accepted")
            .addrs,
        vec![ip]
    );
    assert_eq!(
        parse_dns_hint_line(&make_line(now_unix()))
            .expect("an honest stamp must be accepted")
            .addrs,
        vec![ip]
    );
}

#[test]
fn parse_persisted_line_rejects_future_timestamps() {
    let host = "persisted-future.test.invalid";
    let ip: IpAddr = "203.0.113.76".parse().unwrap();
    let make_line = |stamp: u64| {
        format_persisted_line(
            host,
            &PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: stamp,
            },
        )
    };
    assert!(parse_persisted_line(&make_line(now_unix() + 10 * 24 * 60 * 60)).is_none());
    assert!(parse_persisted_line(&make_line(u64::MAX)).is_none());
    let modest = parse_persisted_line(&make_line(now_unix() + 30)).expect("skew accepted");
    assert_eq!(modest.1.addrs, vec![ip]);
    let honest = parse_persisted_line(&make_line(now_unix())).expect("honest stamp accepted");
    assert_eq!(honest.1.addrs, vec![ip]);
}

#[test]
fn load_rejects_future_stamps_and_expired_stamps_but_keeps_fresh_ones() {
    let fresh_host = "load-fresh.test.invalid";
    let expired_host = "load-expired.test.invalid";
    let future_host = "load-future.test.invalid";
    let ip_a: IpAddr = "203.0.113.77".parse().unwrap();
    let ip_b: IpAddr = "203.0.113.78".parse().unwrap();
    let ip_c: IpAddr = "203.0.113.79".parse().unwrap();
    let now = now_unix();
    let lines = [
        format_persisted_line(
            fresh_host,
            &PersistedAnswer {
                addrs: vec![ip_a],
                resolved_at_unix: now - 60,
            },
        ),
        format_persisted_line(
            expired_host,
            &PersistedAnswer {
                addrs: vec![ip_b],
                resolved_at_unix: now - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
            },
        ),
        format_persisted_line(
            future_host,
            &PersistedAnswer {
                addrs: vec![ip_c],
                resolved_at_unix: now + 10 * 24 * 60 * 60,
            },
        ),
    ];
    let dir = std::env::temp_dir().join(format!("load-stamps-{}-{now}", fresh_host));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    std::fs::write(&path, lines.join("\n")).unwrap();

    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(fresh_host), Some(vec![ip_a]));
    // `expired_host` parsed fine (its stamp is not in the future) and is
    // loaded into the raw store same as ever; age-based filtering has
    // always happened at READ time via `disk_fallback_answer`, not at
    // load time -- this is unrelated to the future-timestamp guard below
    // and unchanged by it.
    assert_eq!(disk_fallback_answer(expired_host), None);
    // `future_host`'s stamp is rejected by `parse_persisted_line` itself
    // (TS4-06), so it never even enters the raw store.
    assert!(!disk_fallback_store()
        .lock()
        .unwrap()
        .contains_key(future_host));

    // A correctly-stamped hint for the formerly-forged host still applies.
    seed_disk_fallback(&[DnsHint {
        host: future_host.to_owned(),
        addrs: vec![ip_c],
        resolved_at_unix: now_unix(),
    }]);
    assert_eq!(disk_fallback_answer(future_host), Some(vec![ip_c]));

    let _ = std::fs::remove_dir_all(&dir);
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.remove(fresh_host);
        store.remove(expired_host);
        store.remove(future_host);
    }
}
