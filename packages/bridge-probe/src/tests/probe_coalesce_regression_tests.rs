use crate::dns::*;
use crate::dns_publish_pause::*;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[tokio::test]
async fn a_fresh_same_generation_answer_wins_over_a_parked_failure() {
    let _serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let host = "same-generation-failure-race.test.invalid";
    forget_dns_answer(host);
    disarm_pre_publish_pause();
    disarm_critical_section_pause();

    let expected_gen = DNS_NETWORK_GENERATION.load(Ordering::SeqCst);
    let gate = arm_pre_publish_pause();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let host_owned = host.to_owned();
    std::thread::spawn(move || {
        let result = remember_doh_failure_if_generation(&host_owned, expected_gen);
        let _ = result_tx.send(result);
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !pre_publish_pause_parked() {
        assert!(
            std::time::Instant::now() < deadline,
            "the stale failure must reach the deterministic race gate"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let ips = vec!["203.0.113.99".parse().unwrap()];
    remember_doh_answer(host, &ips, Duration::from_secs(300));
    gate.release();
    assert!(
        !result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the stale failure finishes"),
        "a stale failure must not replace a fresh same-generation answer"
    );
    assert!(matches!(
        cached_doh_answer(host),
        Some(CacheHit::Addrs(ref addrs)) if addrs == &ips
    ));

    disarm_pre_publish_pause();
    disarm_critical_section_pause();
    forget_dns_answer(host);
}
