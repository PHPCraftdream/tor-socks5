use crate::dns::*;
use crate::*;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn flush_then_save_preserves_the_current_session_fallback() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let host = "save-flush-keeps-live.test.invalid";
    let ip: IpAddr = "203.0.113.75".parse().unwrap();
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!(
        "save-flush-keeps-live-{}-{}",
        std::process::id(),
        TEST_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("initial save must succeed");

    flush_dns_cache();
    assert_eq!(
        disk_fallback_answer(host),
        Some(vec![ip]),
        "flush must preserve usable live answers in the fallback store"
    );
    save_persisted_dns_cache(&path)
        .await
        .expect("post-flush save must succeed");

    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);
    assert_eq!(
        disk_fallback_answer(host),
        Some(vec![ip]),
        "flush followed by save must preserve the session answer on disk"
    );

    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    let _ = std::fs::remove_dir_all(&dir);
}
