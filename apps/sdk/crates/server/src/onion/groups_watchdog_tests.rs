//! Tests of the group health verdict, of the supervision loop and of the restart budget — all without Tor, without network and without a host.

use std::collections::BTreeMap;
use std::time::Duration;

use proxy_config::WatchdogConfig;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tor_socks5_onion::host::{OnionHostStatus, ServiceFailure, ServiceState, ServiceStatus};

use super::{
    group_health, maintained, supervise, verdict, wait_for_stop, GenerationEnd, GenerationVerdict,
    GroupHealth, GROUP_START_WINDOW,
};

fn host_status(status: ServiceStatus) -> OnionHostStatus {
    OnionHostStatus {
        services: BTreeMap::from([(
            "svc".to_owned(),
            ServiceState {
                status,
                failure: None,
            },
        )]),
    }
}

/// Every service failed for a reason a new client could still fix.
fn retryable_status() -> OnionHostStatus {
    let mut status = host_status(ServiceStatus::Failed);
    if let Some(state) = status.services.get_mut("svc") {
        state.failure = Some(ServiceFailure::AddressUnavailable {
            limit: Duration::from_secs(120),
        });
    }
    status
}

/// A host status with several services: (nickname, status, typed failure).
fn group_status(services: &[(&str, ServiceStatus, Option<ServiceFailure>)]) -> OnionHostStatus {
    OnionHostStatus {
        services: services
            .iter()
            .map(|(name, status, failure)| {
                (
                    (*name).to_owned(),
                    ServiceState {
                        status: *status,
                        failure: failure.clone(),
                    },
                )
            })
            .collect(),
    }
}

#[test]
fn a_reachable_service_makes_the_client_healthy() {
    assert_eq!(
        group_health(&host_status(ServiceStatus::Running)),
        GroupHealth::Reachable
    );
    assert_eq!(
        group_health(&host_status(ServiceStatus::DegradedReachable)),
        GroupHealth::Reachable,
        "a degraded but reachable service still proves the client works"
    );
}

#[test]
fn a_service_that_is_still_starting_is_no_verdict_yet() {
    assert_eq!(
        group_health(&host_status(ServiceStatus::Bootstrapping)),
        GroupHealth::Starting
    );
    assert_eq!(
        group_health(&host_status(ServiceStatus::Recovering)),
        GroupHealth::Starting
    );
    assert_eq!(
        group_health(&OnionHostStatus::default()),
        GroupHealth::Starting
    );
}

#[test]
fn a_spent_address_wait_is_a_retryable_failure() {
    assert_eq!(group_health(&retryable_status()), GroupHealth::Retryable);
}

#[test]
fn a_key_or_configuration_failure_is_fatal() {
    let mut status = host_status(ServiceStatus::Failed);
    if let Some(state) = status.services.get_mut("svc") {
        state.failure = Some(ServiceFailure::IdentityChanged);
    }
    assert_eq!(group_health(&status), GroupHealth::Fatal);
    assert_eq!(
        group_health(&host_status(ServiceStatus::Failed)),
        GroupHealth::Fatal,
        "a failure without a typed reason is not one a new client can be trusted to fix"
    );
    assert_eq!(
        group_health(&host_status(ServiceStatus::Stopped)),
        GroupHealth::Fatal
    );
}

#[test]
fn a_running_service_keeps_the_group_up_whatever_a_neighbour_does() {
    let failed = Some(ServiceFailure::IdentityChanged);
    for services in [
        [
            ("a", ServiceStatus::Failed, failed.clone()),
            ("b", ServiceStatus::Running, None),
        ],
        [
            ("a", ServiceStatus::Running, None),
            ("b", ServiceStatus::Failed, failed.clone()),
        ],
    ] {
        assert_eq!(
            group_health(&group_status(&services)),
            GroupHealth::Reachable,
            "the verdict must not depend on the order of the service names"
        );
    }
}

#[test]
fn a_running_service_beats_a_starting_neighbour_whatever_the_order() {
    for status in [ServiceStatus::Running, ServiceStatus::DegradedReachable] {
        for services in [
            [
                ("a", ServiceStatus::Bootstrapping, None),
                ("b", status, None),
            ],
            [
                ("a", status, None),
                ("b", ServiceStatus::Bootstrapping, None),
            ],
            [("a", ServiceStatus::Recovering, None), ("b", status, None)],
        ] {
            assert_eq!(
                group_health(&group_status(&services)),
                GroupHealth::Reachable,
                "a service still starting must not hide a reachable one"
            );
        }
    }
}

#[test]
fn a_group_is_terminal_only_when_no_service_runs() {
    let retry = Some(ServiceFailure::AddressUnavailable {
        limit: Duration::from_secs(120),
    });
    let unfixable = Some(ServiceFailure::IdentityChanged);
    for services in [
        [
            ("a", ServiceStatus::Failed, unfixable.clone()),
            ("b", ServiceStatus::Failed, retry.clone()),
        ],
        [
            ("a", ServiceStatus::Failed, retry.clone()),
            ("b", ServiceStatus::Failed, unfixable.clone()),
        ],
    ] {
        assert_eq!(
            group_health(&group_status(&services)),
            GroupHealth::Fatal,
            "one failure no client can fix makes the group fatal, whatever the order"
        );
    }
    for services in [
        [
            ("a", ServiceStatus::Failed, retry.clone()),
            ("b", ServiceStatus::Failed, retry.clone()),
        ],
        [
            ("b", ServiceStatus::Failed, retry.clone()),
            ("a", ServiceStatus::Failed, retry.clone()),
        ],
    ] {
        assert_eq!(
            group_health(&group_status(&services)),
            GroupHealth::Retryable
        );
    }
}

#[test]
fn a_starting_service_keeps_the_group_starting() {
    let unfixable = Some(ServiceFailure::IdentityChanged);
    for services in [
        [
            ("a", ServiceStatus::Failed, unfixable.clone()),
            ("b", ServiceStatus::Bootstrapping, None),
        ],
        [
            ("a", ServiceStatus::Bootstrapping, None),
            ("b", ServiceStatus::Failed, unfixable.clone()),
        ],
    ] {
        assert_eq!(
            group_health(&group_status(&services)),
            GroupHealth::Starting
        );
    }
}

#[test]
fn a_retryable_host_gets_a_new_client_only_while_the_budget_lasts() {
    let window = Duration::from_secs(180);
    assert_eq!(
        verdict(GroupHealth::Retryable, Duration::ZERO, window, true),
        GenerationVerdict::Restart,
        "a spent address wait may still be fixed by a new client"
    );
    assert_eq!(
        verdict(GroupHealth::Retryable, Duration::ZERO, window, false),
        GenerationVerdict::Stop
    );
}

#[test]
fn a_fatal_host_stops_the_group_whatever_the_budget() {
    let window = Duration::from_secs(180);
    assert_eq!(
        verdict(GroupHealth::Fatal, Duration::ZERO, window, true),
        GenerationVerdict::Stop,
        "a new client cannot fix a key or configuration failure"
    );
}

#[test]
fn a_client_without_a_reachable_service_is_recreated_after_its_window() {
    let window = Duration::from_secs(180);
    assert_eq!(
        verdict(
            GroupHealth::Starting,
            window - Duration::from_secs(1),
            window,
            false
        ),
        GenerationVerdict::Running
    );
    assert_eq!(
        verdict(GroupHealth::Starting, window, window, false),
        GenerationVerdict::Restart
    );
    assert_eq!(
        verdict(GroupHealth::Reachable, window * 10, window, false),
        GenerationVerdict::Running,
        "a reachable group is never restarted for being slow"
    );
}

#[test]
fn the_watchdog_section_decides_whether_a_group_is_maintained() {
    assert!(maintained(WatchdogConfig::default()));
    assert!(
        !maintained(WatchdogConfig {
            enabled: false,
            ..WatchdogConfig::default()
        }),
        "a disabled watchdog leaves groups alone too"
    );
    assert!(!maintained(WatchdogConfig {
        check_interval_secs: 0,
        ..WatchdogConfig::default()
    }));
}

#[tokio::test(start_paused = true)]
async fn a_client_that_never_gets_reachable_is_recreated_at_its_start_window() {
    let (_sender, mut status) = watch::channel(host_status(ServiceStatus::WaitingForSlot));
    let token = CancellationToken::new();
    let started = tokio::time::Instant::now();
    let end = supervise(
        &mut status,
        &token,
        GROUP_START_WINDOW,
        Duration::from_secs(180),
        false,
    )
    .await;
    assert_eq!(end, GenerationEnd::Restart);
    assert_eq!(
        started.elapsed(),
        GROUP_START_WINDOW,
        "a client that never publishes gets its start window, then a new client"
    );
}

#[tokio::test(start_paused = true)]
async fn a_client_that_loses_its_services_is_recreated_after_the_stale_window() {
    let (sender, mut status) = watch::channel(host_status(ServiceStatus::Running));
    let token = CancellationToken::new();
    let started = tokio::time::Instant::now();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        sender.send_replace(host_status(ServiceStatus::Bootstrapping));
    });
    let stale = Duration::from_secs(180);
    let end = supervise(&mut status, &token, GROUP_START_WINDOW, stale, false).await;
    assert_eq!(end, GenerationEnd::Restart);
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(30) + stale,
        "the stale window counts from the moment the services stopped being reachable"
    );
}

#[tokio::test(start_paused = true)]
async fn a_reachable_client_is_left_alone_until_shutdown() {
    let (sender, mut status) = watch::channel(host_status(ServiceStatus::Running));
    let token = CancellationToken::new();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        sender.send_replace(host_status(ServiceStatus::DegradedReachable));
        tokio::time::sleep(Duration::from_secs(3600)).await;
        sender.send_replace(host_status(ServiceStatus::Running));
    });
    let canceller = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(7200)).await;
        canceller.cancel();
    });
    let end = supervise(
        &mut status,
        &token,
        GROUP_START_WINDOW,
        Duration::from_secs(180),
        true,
    )
    .await;
    assert_eq!(
        end,
        GenerationEnd::Cancelled,
        "a group that keeps a reachable service is never re-created"
    );
}

#[tokio::test(start_paused = true)]
async fn cancelling_the_server_token_ends_the_supervisor() {
    let (_sender, mut status) = watch::channel(host_status(ServiceStatus::Running));
    let token = CancellationToken::new();
    token.cancel();
    let end = supervise(
        &mut status,
        &token,
        GROUP_START_WINDOW,
        Duration::from_secs(180),
        false,
    )
    .await;
    assert_eq!(end, GenerationEnd::Cancelled);
}

#[tokio::test(start_paused = true)]
async fn an_all_failed_host_gets_one_more_client_before_giving_up() {
    let (sender, mut status) = watch::channel(host_status(ServiceStatus::Bootstrapping));
    let token = CancellationToken::new();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        sender.send_replace(retryable_status());
    });
    let end = supervise(
        &mut status,
        &token,
        GROUP_START_WINDOW,
        Duration::from_secs(180),
        true,
    )
    .await;
    assert_eq!(end, GenerationEnd::AllFailed);
}

#[tokio::test(start_paused = true)]
async fn an_all_failed_host_without_budget_stops_the_group() {
    let (_sender, mut status) = watch::channel(retryable_status());
    let token = CancellationToken::new();
    let end = supervise(
        &mut status,
        &token,
        GROUP_START_WINDOW,
        Duration::from_secs(180),
        false,
    )
    .await;
    assert_eq!(end, GenerationEnd::Stop);
}

#[tokio::test(start_paused = true)]
async fn a_fatal_host_ends_the_generation_at_once() {
    let (sender, mut status) = watch::channel(host_status(ServiceStatus::Bootstrapping));
    let token = CancellationToken::new();
    let started = tokio::time::Instant::now();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        sender.send_replace(host_status(ServiceStatus::Failed));
    });
    let end = supervise(
        &mut status,
        &token,
        GROUP_START_WINDOW,
        Duration::from_secs(180),
        true,
    )
    .await;
    assert_eq!(end, GenerationEnd::Stop, "a fatal failure stops the group");
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(5),
        "the group does not wait for a start window it cannot use"
    );
}

#[tokio::test(start_paused = true)]
async fn one_failed_service_does_not_stop_a_running_group() {
    let (_sender, mut status) = watch::channel(group_status(&[
        (
            "a",
            ServiceStatus::Failed,
            Some(ServiceFailure::IdentityChanged),
        ),
        ("b", ServiceStatus::Running, None),
    ]));
    let token = CancellationToken::new();
    let canceller = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        canceller.cancel();
    });
    let end = supervise(
        &mut status,
        &token,
        GROUP_START_WINDOW,
        Duration::from_secs(180),
        false,
    )
    .await;
    assert_eq!(
        end,
        GenerationEnd::Cancelled,
        "a group with a running service is not stopped for a failed neighbour"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stopped_host_is_not_restarted_while_the_watchdog_is_off() {
    let (sender, mut status) = watch::channel(host_status(ServiceStatus::Bootstrapping));
    let token = CancellationToken::new();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        sender.send_replace(host_status(ServiceStatus::Stopped));
    });
    assert!(
        !wait_for_stop(&mut status, &token).await,
        "a stopped host ends the group instead of holding it open"
    );
}

#[tokio::test(start_paused = true)]
async fn wait_for_stop_ends_on_cancellation() {
    let (_sender, mut status) = watch::channel(host_status(ServiceStatus::Bootstrapping));
    let token = CancellationToken::new();
    token.cancel();
    assert!(wait_for_stop(&mut status, &token).await);
}
