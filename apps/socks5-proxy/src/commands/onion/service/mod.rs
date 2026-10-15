//! Server-side onion services: launch config-defined services once Tor is
//! bootstrapped, forward their virtual ports to local `host:port` targets,
//! log lifecycle/status, and hold the onion keystore CLI lock for as long as
//! any service is published (so `tor-socks5 onion new/import/remove` cannot
//! race a live service).
//!
//! Task structure (all under the `onion-service` feature):
//!
//! ```text
//! producer task (one, in `producers`, cancelled via producer_token)
//!   └─ holds the keystore PathLock guard for its whole life
//!      └─ one manager task per enabled service
//!         ├─ launch + retry/backoff loop (30 s doubling to 5 min)
//!         ├─ waits for the .onion address, then spawns:
//!         │   ├─ request-serving task (rendezvous → stream requests → TCP)
//!         │   └─ status-event logging task
//!         └─ keeps the Arc<RunningOnionService> alive until shutdown
//! ```
//!
//! The watchdog heals the Tor client *in place* (it never rebuilds the
//! `TorClient`), so services launched once survive heals; we still read the
//! tunnel through `TorHandle::tunnel()` per launch attempt, like every other
//! subsystem.

pub(crate) mod forward;
pub(crate) mod serve;

#[cfg(test)]
mod lock_tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use proxy_config::OnionServiceEntry;
use safelog::DisplayRedacted as _;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::onion::store;
use crate::tor_watchdog::TorHandle;

/// Delay before the first relaunch attempt after a failed launch; doubles
/// up to [`RETRY_DELAY_MAX`] and stays there for the process' lifetime.
const RETRY_DELAY_INITIAL: Duration = Duration::from_secs(30);
/// Upper bound on the launch retry backoff.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(300);
/// Poll interval while waiting for the service's `.onion` address to become
/// available (arti finds or generates the identity key asynchronously).
const ADDRESS_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Total budget for the address wait. Descriptor publication takes much
/// longer than this; the address itself (keystore lookup/generation) should
/// appear within seconds.
const ADDRESS_WAIT_LIMIT: Duration = Duration::from_secs(120);

/// Spawn the onion-service producer if any configured service is enabled.
/// Appends the producer's join handle to `producers` (cancelled and joined by
/// the server's regular shutdown choreography). No-op when nothing is
/// enabled: default configs keep today's behavior exactly.
pub(crate) fn spawn_services(
    handle: TorHandle,
    entries: &[OnionServiceEntry],
    config_path: Option<&Path>,
    token: CancellationToken,
    producers: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    let enabled: Vec<OnionServiceEntry> = entries
        .iter()
        .filter(|entry| entry.enabled)
        .cloned()
        .collect();
    if enabled.is_empty() {
        return;
    }
    info!(count = enabled.len(), "starting configured onion services");
    let config_path = config_path.map(Path::to_path_buf);
    producers.push(tokio::spawn(run_services(
        handle,
        enabled,
        config_path,
        token,
    )));
}

/// Producer task body: acquire the keystore lock (held for the services'
/// lifetime), then run one manager task per service until shutdown.
async fn run_services(
    handle: TorHandle,
    entries: Vec<OnionServiceEntry>,
    config_path: Option<PathBuf>,
    token: CancellationToken,
) {
    // The lock acquisition blocks (file lock + poll loop), so it runs on the
    // blocking pool; the guard then moves into this task and lives until the
    // task ends — i.e. until shutdown cancels the managers and they are
    // joined below. Failing to get it is NOT fatal: the proxy keeps running
    // without onion services.
    let dir = store::keystore_dir(config_path.as_deref());
    let lock = tokio::task::spawn_blocking(move || store::lock(&dir)).await;
    let _lock = match lock {
        Ok(Ok(guard)) => Some(guard),
        Ok(Err(error)) => {
            error!(
                %error,
                "onion services not started: the onion keystore lock is held \
                 elsewhere (a tor-socks5 onion command or another server instance?)"
            );
            return;
        }
        Err(error) => {
            error!(%error, "onion services not started: lock task panicked");
            return;
        }
    };

    // One manager per service; a failing service must not affect the others.
    let mut managers = Vec::with_capacity(entries.len());
    for entry in entries {
        managers.push(tokio::spawn(service_manager(
            handle.clone(),
            entry,
            config_path.clone(),
            token.clone(),
        )));
    }
    // Join the managers so the keystore lock guard is only dropped after
    // every service stopped. Managers exit promptly on cancellation.
    for manager in managers {
        if let Err(error) = manager.await {
            warn!(%error, "onion service manager task ended with a join error");
        }
    }
}

/// Launch (and if necessary relaunch) one service, then keep it alive until
/// shutdown. Holding the `Arc<RunningOnionService>` here is what keeps the
/// service published.
async fn service_manager(
    handle: TorHandle,
    entry: OnionServiceEntry,
    config_path: Option<PathBuf>,
    token: CancellationToken,
) {
    let nick = entry.nickname.clone();
    let nick_hs = match store::nickname(&nick) {
        Ok(nick) => nick,
        Err(error) => {
            error!(nickname = %nick, %error, "invalid onion service nickname; service not started");
            return;
        }
    };
    let config = match build_config(nick_hs) {
        Ok(config) => config,
        Err(error) => {
            error!(nickname = %nick, %error, "invalid onion service configuration; service not started");
            return;
        }
    };
    // Observable enough to tell the user which identity is published: if the
    // keystore already holds the identity key (from `onion new`/`import`),
    // arti uses it; otherwise arti generates a fresh one on first launch.
    match identity_exists(config_path.as_deref(), &nick) {
        Ok(true) => info!(nickname = %nick, "onion service: using existing identity key"),
        Ok(false) => info!(
            nickname = %nick,
            "onion service: no identity key in keystore; one will be generated on first launch"
        ),
        Err(error) => {
            warn!(nickname = %nick, %error, "could not inspect the onion keystore before launch")
        }
    }

    let ports = serve::port_map(&entry.ports);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(serve::MAX_CONCURRENT_STREAMS));

    let mut delay = RETRY_DELAY_INITIAL;
    loop {
        // Snapshot the current tunnel; `None` only while shutting down. The
        // watchdog heals the client in place, so a launch that succeeded
        // never needs repeating after a heal.
        let tunnel = tokio::select! {
            biased;
            () = token.cancelled() => return,
            tunnel = handle.tunnel() => tunnel,
        };
        let Some(tunnel) = tunnel else {
            debug!(nickname = %nick, "onion service launch aborted: Tor is shutting down");
            return;
        };

        match tunnel.raw().launch_onion_service(config.clone()) {
            Ok(Some((service, rend_requests))) => {
                let Some(address) = wait_for_address(&service, &token, &nick).await else {
                    return; // shutdown while waiting
                };
                info!(
                    nickname = %nick,
                    address = %address.display_unredacted(),
                    "onion service address available: onion service starting"
                );
                // Serving loop and status logger run as independent tasks;
                // both exit on cancellation. The manager keeps this first
                // clone alive; dropping the last clone would unpublish the
                // service.
                let serving = tokio::spawn(serve::serve_service(
                    service.clone(),
                    rend_requests,
                    ports,
                    semaphore,
                    token.clone(),
                ));
                let status = tokio::spawn(serve::log_status_events(
                    service.status_events(),
                    nick.clone(),
                    address.display_unredacted().to_string(),
                    token.clone(),
                ));
                token.cancelled().await;
                let _ = serving.await;
                let _ = status.await;
                info!(nickname = %nick, "onion service stopped");
                return;
            }
            // `enabled` defaults to true in our built config; `None` means
            // arti refused to start the service at all.
            Ok(None) => {
                error!(nickname = %nick, "onion service was rejected by the Tor client (disabled configuration); not retried");
                return;
            }
            Err(error) => {
                error!(
                    nickname = %nick,
                    %error,
                    retry_in = ?delay,
                    "failed to launch onion service; retrying"
                );
            }
        }

        tokio::select! {
            biased;
            () = token.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(RETRY_DELAY_MAX);
    }
}

/// Build arti's config for a (pre-validated) nickname.
fn build_config(nick: tor_hsservice::HsNickname) -> Result<tor_hsservice::OnionServiceConfig> {
    tor_hsservice::config::OnionServiceConfigBuilder::default()
        .nickname(nick)
        .build()
        .context("building the onion service configuration")
}

/// Whether the keystore already holds an identity key for `nick`.
fn identity_exists(config_path: Option<&Path>, nick: &str) -> Result<bool> {
    let dir = store::keystore_dir(config_path);
    let keymgr = store::open(&dir)?;
    let nick = store::nickname(nick)?;
    store::exists(&keymgr, &nick)
}

/// Poll for the service's `.onion` address, bounded by
/// [`ADDRESS_WAIT_LIMIT`]. Returns `None` on shutdown.
async fn wait_for_address(
    service: &Arc<tor_hsservice::RunningOnionService>,
    token: &CancellationToken,
    nick: &str,
) -> Option<tor_hscrypto::pk::HsId> {
    let deadline = tokio::time::Instant::now() + ADDRESS_WAIT_LIMIT;
    loop {
        if let Some(address) = service.onion_address() {
            return Some(address);
        }
        if tokio::time::Instant::now() >= deadline {
            error!(
                nickname = %nick,
                waited = ?ADDRESS_WAIT_LIMIT,
                "onion service address never became available"
            );
            return None;
        }
        tokio::select! {
            biased;
            () = token.cancelled() => return None,
            () = tokio::time::sleep(ADDRESS_POLL_INTERVAL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_accepts_valid_nickname() {
        let nick = store::nickname("svc-one").expect("nickname");
        let config = build_config(nick).expect("config");
        assert_eq!(config.nickname().to_string(), "svc-one");
        // `enabled` defaults to true, so arti will actually start it.
        assert!(config.enabled());
    }

    #[test]
    fn invalid_nickname_is_rejected_before_launch() {
        let entry = OnionServiceEntry {
            nickname: "not a nickname".to_owned(),
            enabled: true,
            ports: Vec::new(),
        };
        // The manager returns without launching when the nickname is invalid;
        // validate that path directly via the store helper it uses.
        assert!(store::nickname(&entry.nickname).is_err());
    }
}
