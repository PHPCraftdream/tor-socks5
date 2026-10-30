use super::*;
use crate::bridge_verifier::{AdmissionWorkers, TestWorkers};
use crate::test_seams::{ParkedGate, Site, HANG_GUARD};
use std::sync::Arc;

#[tokio::test]
async fn cancelled_drain_keeps_promotion_worker_owned() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.transport = "webtunnel".into();
    cfg.write(&path).unwrap();
    let candidate: BridgeLine = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge".parse().unwrap();
    let pool_path = CandidatePool::resolve_path(Some(&path));
    let mut pool = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(pool.merge([candidate.clone()], &HashSet::new()), 1);
    pool.save().unwrap();

    let gate = ParkedGate::arm(Site::ConfigPromotion, &path);
    let registry = Arc::new(TestWorkers::default());
    let owner = registry.clone();
    let drain_path = path.clone();
    let outer = tokio::spawn(async move {
        owner
            .scope(async move {
                let probe: ProbeCheck<'static> = Box::new(|_| {
                    Box::pin(async {
                        bridge_probe::Outcome::Reachable {
                            latency: Duration::from_millis(10),
                        }
                    })
                });
                drain_pool_with(
                    Some(&drain_path),
                    1,
                    None,
                    &probe,
                    &AdmissionWorkers::default(),
                )
                .await
            })
            .await
    });
    let wait = gate.clone();
    tokio::task::spawn_blocking(move || wait.wait_parked(HANG_GUARD))
        .await
        .unwrap();
    outer.abort();
    assert!(outer.await.unwrap_err().is_cancelled());
    let slot = gate
        .promotion_slot()
        .expect("promotion observed")
        .expect("tracked promotion");
    assert!(registry.owns_pending(&slot).await);
    let mut join = Box::pin(registry.join());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(join.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(join);
    gate.release();
    tokio::time::timeout(HANG_GUARD, registry.join())
        .await
        .unwrap()
        .unwrap();
    assert!(registry.cleared(&slot).await);
    assert_eq!(registry.pending_count().await, 0);
    let latest = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(latest
        .bridges
        .parsed()
        .unwrap()
        .bridges
        .contains(&candidate));
    let mut pool = CandidatePool::load(pool_path).unwrap();
    assert_eq!(pool.take(1), vec![candidate]);
}
