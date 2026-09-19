//! The two sides of bridge DNS in `bridge-probe`:
//!
//! * portable [`bridge_probe::DnsHint`] lines: format/parse, import into
//!   the process-local fallback store via `seed_disk_fallback`, read back
//!   read-only via `best_known_answer`;
//! * live resolution through the built-in multi-provider DoH pool via
//!   `resolve_addrs` (network access; failures come back as `Err`,
//!   never a panic).
//!
//! Run with: `cargo run --example dns_lookup -p bridge-probe`

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bridge_line::BridgeLine;
use bridge_probe::{
    best_known_answer, dns_hostname_of, format_dns_hint_line, parse_dns_hint_line, resolve_addrs,
    seed_disk_fallback, DnsHint, ResolverPolicy,
};

fn main() {
    // The crate's tokio features enable `rt`, not `rt-multi-thread`, so
    // the demo builds the current-thread runtime explicitly.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime")
        .block_on(run());
}

async fn run() {
    offline_part();
    online_part().await;
    bridge_part();
}

fn offline_part() {
    // A hint is a fact about the internet — (host, addrs, resolved_at) —
    // shareable across devices and processes, e.g. alongside a QR-shared
    // bridge line.
    let hint = DnsHint {
        host: "fronting.example.test".to_owned(),
        addrs: vec!["203.0.113.9".parse::<IpAddr>().expect("valid ip")],
        resolved_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_secs(),
    };

    let line = format_dns_hint_line(&hint);
    println!("hint line: {line}");
    println!(
        "round-trips: {}",
        parse_dns_hint_line(&line) == Some(hint.clone())
    );
    println!(
        "a plain bridge line is not a hint: {}",
        parse_dns_hint_line("obfs4 1.2.3.4:80 ABCDEF cert=ZZZ iat-mode=0").is_none()
    );

    // Import into the in-process fallback store, then query it read-only.
    // `best_known_answer` never resolves: it serves the live DoH cache or
    // the fallback store, and None means "nothing known".
    seed_disk_fallback(std::slice::from_ref(&hint));
    println!(
        "best_known_answer after import: {:?}",
        best_known_answer("fronting.example.test").map(|h| h.addrs)
    );
    println!(
        "best_known_answer for an unknown host: {}",
        best_known_answer("never-resolved.example.test").is_none()
    );
}

async fn online_part() {
    // Live resolution through the shared DoH pool. Bounded by an outer
    // demo timeout; on total provider failure `resolve_addrs` reports
    // `Err(String)` — the pool remembers the failure internally, and
    // later calls can fall back to stale or persisted answers.
    let attempt = tokio::time::timeout(
        Duration::from_secs(45),
        resolve_addrs("example.org", 443, ResolverPolicy::default()),
    )
    .await;
    match attempt {
        Ok(Ok(addrs)) => {
            println!(
                "resolve_addrs(example.org:443) -> {} address(es):",
                addrs.len()
            );
            for addr in addrs {
                println!("  {addr}");
            }
        }
        Ok(Err(message)) => println!("resolution failed (offline?): {message}"),
        Err(_) => println!("resolution exceeded the 45s demo budget"),
    }
}

fn bridge_part() {
    // Only webtunnel bridges whose real target is a `url=` hostname cost
    // a DNS lookup; IP-literal targets have nothing to hint at.
    let webtunnel: BridgeLine =
        "webtunnel 192.0.2.3:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://fronting.example.test/x"
            .parse()
            .expect("valid webtunnel line");
    let obfs4: BridgeLine =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
            .parse()
            .expect("valid obfs4 line");
    println!(
        "webtunnel bridge needs resolved: {:?}",
        dns_hostname_of(&webtunnel)
    );
    println!(
        "obfs4 bridge needs resolved:     {:?}",
        dns_hostname_of(&obfs4)
    );
}
