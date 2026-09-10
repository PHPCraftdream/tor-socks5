use crate::dns::*;
use crate::*;

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
