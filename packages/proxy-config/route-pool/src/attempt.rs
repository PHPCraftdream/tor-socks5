use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use resocks5_net::types::ProxyConfig;

use crate::scope::PoolScope;

/// Longest share of the overall deadline a member may use while others remain.
const ATTEMPT_BUDGET: Duration = Duration::from_secs(15);

/// Who is to blame for a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The proxy itself looks down or broken; counts toward quarantine.
    ProxyHard,
    /// The proxy failed in a way that may be transient; lowers its rating only.
    ProxySoft,
    /// Not the proxy's fault (target, Tor, local): rating untouched, no rotation.
    NotProxy,
    /// The member cannot serve right now and nothing is wrong with it (for
    /// example its client is still starting): the next member is tried and
    /// nothing is recorded. A member that serves after a skip does not pin
    /// the site, so the skipped one is used again once it is ready.
    Skip,
}

/// Why no member of the pool produced a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum PoolError<E> {
    /// Every member failed, or the deadline ran out. Carries the last failure.
    Exhausted {
        /// Failure of the last member tried, if any was tried.
        last: Option<E>,
    },
    /// A failure that is not the proxy's fault; rotating would not help.
    Aborted(E),
}

/// Tries pool members for `key` one at a time until one connects.
///
/// `connect` receives the member and the deadline of this attempt: fifteen
/// seconds ahead at most while other members remain, and the whole remaining
/// time for the last one, so a single-member pool keeps the full deadline. An
/// attempt never runs past `deadline`. Attempts are strictly
/// sequential, so the target is only ever revealed to one proxy at a time. A
/// failure is classified by `classify`: proxy failures move on to the next
/// member, anything else aborts at once. When members run out the result is
/// [`PoolError::Exhausted`]; the caller must fail the connection, never go
/// direct.
///
/// cancel-safe: NO — dropping the future abandons the attempt in flight and
/// records nothing for it.
pub async fn run_attempts<T, E, F, Fut, C>(
    scope: &PoolScope,
    key: &str,
    deadline: Instant,
    connect: F,
    classify: C,
) -> Result<T, PoolError<E>>
where
    F: FnMut(Arc<ProxyConfig>, Instant) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    C: Fn(&E) -> Verdict,
{
    run_attempts_with_budget(scope, key, deadline, ATTEMPT_BUDGET, connect, classify).await
}

/// [`run_attempts`] with a caller-chosen share of the deadline per member.
///
/// A hop that must start a whole Tor client on first use needs more than the
/// fifteen seconds a plain proxy dial gets.
///
/// cancel-safe: NO — dropping the future abandons the attempt in flight and
/// records nothing for it.
pub async fn run_attempts_with_budget<T, E, F, Fut, C>(
    scope: &PoolScope,
    key: &str,
    deadline: Instant,
    budget: Duration,
    mut connect: F,
    classify: C,
) -> Result<T, PoolError<E>>
where
    F: FnMut(Arc<ProxyConfig>, Instant) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    C: Fn(&E) -> Verdict,
{
    let mut last = None;
    let mut skipped = false;
    let candidates = scope.candidates(key);
    let count = candidates.len();
    for (index, proxy) in candidates.into_iter().enumerate() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let attempt_deadline = if index + 1 == count {
            deadline
        } else {
            deadline.min(now + budget)
        };
        match connect(Arc::clone(&proxy), attempt_deadline).await {
            Ok(value) => {
                if skipped {
                    scope.record_served(&proxy);
                } else {
                    scope.record_success(&proxy, key);
                }
                return Ok(value);
            }
            Err(error) => match classify(&error) {
                Verdict::Skip => skipped = true,
                Verdict::ProxyHard => {
                    scope.record_failure(&proxy, true);
                    last = Some(error);
                }
                Verdict::ProxySoft => {
                    scope.record_failure(&proxy, false);
                    last = Some(error);
                }
                Verdict::NotProxy => return Err(PoolError::Aborted(error)),
            },
        }
    }
    Err(PoolError::Exhausted { last })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use client_acl::ProxyPool;

    use super::*;

    fn scope(members: &[&str]) -> PoolScope {
        let pool = ProxyPool::new(members.iter().map(|m| m.parse().unwrap()).collect()).unwrap();
        PoolScope::new(&pool).unwrap()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn classify(error: &&'static str) -> Verdict {
        match *error {
            "hard" => Verdict::ProxyHard,
            "soft" => Verdict::ProxySoft,
            "skip" => Verdict::Skip,
            _ => Verdict::NotProxy,
        }
    }

    #[tokio::test]
    async fn a_skipped_member_is_not_penalised_and_does_not_pin_the_site() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let order = scope.candidates("example.com");
        let skipped = order[0].clone();
        let served = run_attempts(
            &scope,
            "example.com",
            far(),
            |proxy, _| {
                let skip = proxy.host == skipped.host;
                async move {
                    if skip {
                        Err("skip")
                    } else {
                        Ok(proxy.host.clone())
                    }
                }
            },
            classify,
        )
        .await
        .unwrap();
        assert_ne!(served, skipped.host);
        assert!(!scope.is_quarantined(&skipped));
        let next = scope.candidates("example.com");
        assert_eq!(
            next[0].host, skipped.host,
            "the skipped member keeps the site until it can serve"
        );
    }

    #[tokio::test]
    async fn the_attempt_budget_is_chosen_by_the_caller() {
        let pair = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let overall = Instant::now() + Duration::from_secs(3600);
        let deadlines = Mutex::new(Vec::new());
        let _: Result<(), PoolError<&'static str>> = run_attempts_with_budget(
            &pair,
            "example.com",
            overall,
            Duration::from_secs(30),
            |_, attempt| {
                deadlines.lock().unwrap().push(attempt);
                async { Err("soft") }
            },
            classify,
        )
        .await;
        let deadlines = deadlines.into_inner().unwrap();
        let first = deadlines[0] - Instant::now();
        assert!(first > Duration::from_secs(15) && first <= Duration::from_secs(30));
        assert_eq!(deadlines[1], overall);
    }

    #[tokio::test]
    async fn rotates_past_proxy_failures_and_keeps_the_working_member() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080", "192.0.2.3:1080"]);
        let tried = Mutex::new(Vec::new());
        let result = run_attempts(
            &scope,
            "example.com",
            far(),
            |proxy, _| {
                let works = {
                    let mut tried = tried.lock().unwrap();
                    tried.push(proxy.host.clone());
                    tried.len() == 3
                };
                async move {
                    if works {
                        Ok(proxy.host.clone())
                    } else {
                        Err("hard")
                    }
                }
            },
            classify,
        )
        .await
        .unwrap();
        let tried = tried.into_inner().unwrap();
        assert_eq!(tried.len(), 3);
        assert_eq!(result, tried[2]);
        let next = scope.candidates("example.com");
        assert_eq!(
            next[0].host, result,
            "site must stay on the member that served it"
        );
    }

    #[tokio::test]
    async fn a_failure_that_is_not_the_proxys_aborts_without_rotation() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let calls = Mutex::new(0);
        let result: Result<(), _> = run_attempts(
            &scope,
            "example.com",
            far(),
            |_, _| {
                *calls.lock().unwrap() += 1;
                async { Err("target") }
            },
            classify,
        )
        .await;
        assert_eq!(result, Err(PoolError::Aborted("target")));
        assert_eq!(*calls.lock().unwrap(), 1);
        for member in scope.candidates("example.com") {
            assert!(!scope.is_quarantined(&member));
        }
    }

    #[tokio::test]
    async fn an_exhausted_pool_fails_and_reports_the_last_error() {
        let scope = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let calls = Mutex::new(0);
        let result: Result<(), _> = run_attempts(
            &scope,
            "example.com",
            far(),
            |_, _| {
                *calls.lock().unwrap() += 1;
                async { Err("soft") }
            },
            classify,
        )
        .await;
        assert_eq!(result, Err(PoolError::Exhausted { last: Some("soft") }));
        assert_eq!(
            *calls.lock().unwrap(),
            2,
            "each member is tried exactly once"
        );
    }

    #[tokio::test]
    async fn an_expired_deadline_tries_nothing() {
        let scope = scope(&["192.0.2.1:1080"]);
        let calls = Mutex::new(0);
        let result: Result<(), PoolError<&'static str>> = run_attempts(
            &scope,
            "example.com",
            Instant::now(),
            |_, _| {
                *calls.lock().unwrap() += 1;
                async { Ok(()) }
            },
            classify,
        )
        .await;
        assert_eq!(result, Err(PoolError::Exhausted { last: None }));
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn the_last_member_gets_the_whole_remaining_deadline() {
        let overall = Instant::now() + Duration::from_secs(3600);
        let single = scope(&["192.0.2.1:1080"]);
        let seen = Mutex::new(None);
        let _: Result<(), PoolError<&'static str>> = run_attempts(
            &single,
            "example.com",
            overall,
            |_, attempt| {
                *seen.lock().unwrap() = Some(attempt);
                async { Ok(()) }
            },
            classify,
        )
        .await;
        assert_eq!(seen.into_inner().unwrap().unwrap(), overall);

        let pair = scope(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let deadlines = Mutex::new(Vec::new());
        let _: Result<(), PoolError<&'static str>> = run_attempts(
            &pair,
            "example.com",
            overall,
            |_, attempt| {
                deadlines.lock().unwrap().push(attempt);
                async { Err("soft") }
            },
            classify,
        )
        .await;
        let deadlines = deadlines.into_inner().unwrap();
        assert_eq!(deadlines.len(), 2);
        assert!(deadlines[0] < overall, "a non-last member is time-boxed");
        assert_eq!(deadlines[1], overall);
    }

    #[tokio::test]
    async fn attempt_deadlines_never_pass_the_overall_deadline() {
        let scope = scope(&["192.0.2.1:1080"]);
        let overall = Instant::now() + Duration::from_secs(3);
        let seen = Mutex::new(None);
        let _: Result<(), PoolError<&'static str>> = run_attempts(
            &scope,
            "example.com",
            overall,
            |_, attempt| {
                *seen.lock().unwrap() = Some(attempt);
                async { Ok(()) }
            },
            classify,
        )
        .await;
        assert!(seen.into_inner().unwrap().unwrap() <= overall);
    }
}
