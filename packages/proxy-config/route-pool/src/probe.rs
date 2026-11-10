use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use resocks5_net::types::ProxyConfig;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::scope::PoolScope;

/// Longest a single probe may run; below the rotator's 25 s probation lease.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// Probes of one scope that may run at the same time.
const PROBE_CONCURRENCY: usize = 4;

/// What a probe learned about a quarantined member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The proxy answered: lift the quarantine.
    Alive,
    /// The proxy is still down: extend the quarantine.
    Dead,
    /// The probe could not tell (for example Tor itself was unavailable):
    /// change nothing, the member is probed again after its lease.
    Inconclusive,
}

/// Probes every member that is due and applies the outcomes.
///
/// `probe` receives the member and the deadline of the probe. A probe that
/// overruns its deadline counts as [`ProbeOutcome::Dead`]. Stale claims (the
/// member changed state meanwhile) are ignored by the scope.
pub async fn probe_round<P, Fut>(scope: &Arc<PoolScope>, probe: &P)
where
    P: Fn(Arc<ProxyConfig>, Instant) -> Fut,
    Fut: Future<Output = ProbeOutcome> + Send + 'static,
{
    let mut running = JoinSet::new();
    let mut claims = scope.take_probe_claims().into_iter();
    loop {
        while running.len() < PROBE_CONCURRENCY {
            let Some(claim) = claims.next() else { break };
            let deadline = Instant::now() + PROBE_TIMEOUT;
            let attempt = probe(Arc::clone(&claim.proxy), deadline);
            running.spawn(async move {
                let outcome = tokio::time::timeout(PROBE_TIMEOUT, attempt)
                    .await
                    .unwrap_or(ProbeOutcome::Dead);
                (claim, outcome)
            });
        }
        let Some(done) = running.join_next().await else {
            break;
        };
        let Ok((claim, outcome)) = done else { continue };
        match outcome {
            ProbeOutcome::Alive => {
                scope.probe_succeeded(&claim);
            }
            ProbeOutcome::Dead => {
                scope.probe_failed(&claim);
            }
            ProbeOutcome::Inconclusive => {}
        }
    }
}

/// Runs [`probe_round`] over the scopes `scopes` returns every `interval`
/// until `cancel` fires.
///
/// `scopes` is asked again on every tick, so pools created later are picked up.
/// Cancellation drops the round in flight; outstanding probes are aborted with
/// it and their claims expire on their own.
pub async fn drive_probes<S, P, Fut>(
    scopes: S,
    interval: Duration,
    probe: P,
    cancel: CancellationToken,
) where
    S: Fn() -> Vec<Arc<PoolScope>>,
    P: Fn(Arc<ProxyConfig>, Instant) -> Fut,
    Fut: Future<Output = ProbeOutcome> + Send + 'static,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            _ = ticker.tick() => {
                for scope in scopes() {
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => return,
                        () = probe_round(&scope, &probe) => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use client_acl::ProxyPool;

    use super::*;

    fn scope(members: &[&str]) -> Arc<PoolScope> {
        let pool = ProxyPool::new(members.iter().map(|m| m.parse().unwrap()).collect()).unwrap();
        Arc::new(PoolScope::new(&pool).unwrap())
    }

    fn quarantine(scope: &PoolScope, proxy: &Arc<ProxyConfig>) {
        for _ in 0..3 {
            scope.record_failure(proxy, true);
        }
        assert!(scope.is_quarantined(proxy));
    }

    #[tokio::test]
    async fn an_alive_probe_lifts_the_quarantine() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let down = scope.candidates("example.com")[0].clone();
        quarantine(&scope, &down);
        scope.make_probe_due(&down);
        probe_round(&scope, &|_, _| async { ProbeOutcome::Alive }).await;
        assert!(!scope.is_quarantined(&down));
        assert_eq!(scope.candidates("example.com").len(), 2);
    }

    #[tokio::test]
    async fn a_dead_probe_keeps_the_member_out_of_rotation() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let down = scope.candidates("example.com")[0].clone();
        quarantine(&scope, &down);
        scope.make_probe_due(&down);
        probe_round(&scope, &|_, _| async { ProbeOutcome::Dead }).await;
        assert!(scope.is_quarantined(&down));
        assert_eq!(scope.candidates("example.com").len(), 1);
    }

    #[tokio::test]
    async fn an_inconclusive_probe_changes_nothing() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let down = scope.candidates("example.com")[0].clone();
        quarantine(&scope, &down);
        scope.make_probe_due(&down);
        probe_round(&scope, &|_, _| async { ProbeOutcome::Inconclusive }).await;
        assert!(scope.is_quarantined(&down));
    }

    #[tokio::test]
    async fn members_that_are_not_due_are_not_probed() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let down = scope.candidates("example.com")[0].clone();
        quarantine(&scope, &down);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        probe_round(&scope, &move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            async { ProbeOutcome::Alive }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(scope.is_quarantined(&down));
    }

    #[tokio::test]
    async fn the_driver_stops_when_cancelled() {
        let scope = scope(&["192.0.2.1:1080"]);
        let cancel = CancellationToken::new();
        let driver = tokio::spawn(drive_probes(
            move || vec![Arc::clone(&scope)],
            Duration::from_secs(3600),
            |_, _| async { ProbeOutcome::Alive },
            cancel.clone(),
        ));
        cancel.cancel();
        driver.await.expect("driver must finish after cancellation");
    }
}
