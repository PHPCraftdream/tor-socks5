//! Thin shell over the library's onion-service host
//! (`tor_socks5_onion::host`): refresh the enabled services from the config
//! file after bootstrap and hand them, the keystore directory and the config
//! path to the host. The launch choreography, the launch logs, the keystore
//! lock and the status snapshot all live in the library crate.

use std::path::Path;
use std::sync::Arc;

use arti_wrapper::Settings;
use proxy_config::{Config, OnionServiceEntry, WatchdogConfig};
use tokio_util::sync::CancellationToken;

use super::groups;
use tor_socks5_onion::host::OnionHostConfig;
use tor_socks5_runtime::tor_watchdog::TorHandle;

/// Spawn the onion-service host producer if any configured service is
/// enabled. Appends the producer's join handle to `producers` (cancelled and
/// joined by the server's regular shutdown choreography). No-op when nothing
/// is enabled: default configs keep today's behavior exactly.
///
/// The "starting configured onion services" info line (and the soft-limit
/// warning) now live in the library's `start()`; this shell logs nothing.
pub(crate) fn spawn_services(
    handle: TorHandle,
    settings: Settings,
    entries: &[OnionServiceEntry],
    config_path: &Path,
    watchdog: WatchdogConfig,
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

    let config_path = config_path.to_path_buf();
    let refresh_config_path = config_path.clone();
    let producer_token = token.clone();
    producers.push(tokio::spawn(async move {
        // Bootstrap may take long enough for `onion new --force` or `onion
        // remove` to change the services file. Refresh only names enabled in
        // the original config snapshot; the host rechecks key identity under
        // its keystore lock before preparing any service.
        let entries = match tor_socks5_runtime::workers::run_fallible_blocking(move || {
            refreshed_enabled_entries(&refresh_config_path, &enabled)
        })
        .await
        {
            Ok(Ok(entries)) => entries,
            Ok(Err(error)) | Err(error) => {
                tracing::warn!(
                    %error,
                    "onion services not started: could not refresh the current onion services file"
                );
                return;
            }
        };
        if entries.is_empty() || producer_token.is_cancelled() {
            return;
        }

        // Services without a bridge group share the process client; each
        // group is hosted by a client of its own on its own bridges.
        let split = groups::split_entries(entries);
        // The shared host holds the process keystore's lock. When every
        // service is in a group, nothing else would, and `onion new`/`remove`
        // must keep refusing while the server runs.
        let _keystore_lock = if split.shared.is_empty() {
            let keystore_dir = tor_socks5_runtime::tor_setup::arti_keystore_dir(&config_path);
            match tor_socks5_runtime::workers::run_fallible_blocking(move || {
                persist_lock::PathLock::acquire_bounded(&keystore_dir, persist_lock::CLI_LOCK_WAIT)
            })
            .await
            {
                Ok(Ok(lock)) => Some(lock),
                Ok(Err(error)) | Err(error) => {
                    tracing::error!(
                        %error,
                        "onion services not started: the onion keystore lock is unavailable \
                         (held by a tor-socks5 onion command or another server instance?)"
                    );
                    return;
                }
            }
        } else {
            None
        };
        let pool = handle.clone();
        let mut hosts = Vec::new();
        if !split.shared.is_empty() {
            let host_config = OnionHostConfig::new(
                handle,
                tor_socks5_runtime::tor_setup::arti_keystore_dir(&config_path),
                token.clone(),
            )
            .with_entries(split.shared)
            .with_config_path(Some(config_path.clone()));
            hosts.push(AbortOnDropHandle::new(
                tor_socks5_onion::host::OnionHost::new(host_config)
                    .start()
                    .detach(),
            ));
        }
        let mut assigned = groups::assign_bridges(&settings.bridges, &split.groups);
        // Every group sees the bridges of the others, so a replacement never
        // takes a bridge another group works with.
        let group_bridges = groups::GroupBridges::new(&assigned);
        for (name, plan) in split.groups {
            let Some(bridges) = assigned.remove(&name) else {
                continue;
            };
            hosts.push(AbortOnDropHandle::new(tokio::spawn(groups::run_group(
                groups::GroupRun {
                    name,
                    plan,
                    assigned: bridges,
                    main: settings.clone(),
                    pool: pool.clone(),
                    groups: Arc::clone(&group_bridges),
                    watchdog,
                    config_path: config_path.clone(),
                    token: token.clone(),
                },
            ))));
        }
        for result in futures::future::join_all(hosts.iter_mut().map(AbortOnDropHandle::join)).await
        {
            if let Err(error) = result {
                tracing::warn!(%error, "onion service producer task ended with a join error");
            }
        }
    }));
}

/// Aborting the supervising producer must also abort the detached host task.
pub(super) struct AbortOnDropHandle<T>(tokio::task::JoinHandle<T>);

impl<T> AbortOnDropHandle<T> {
    pub(super) fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(handle)
    }

    pub(super) async fn join(&mut self) -> Result<T, tokio::task::JoinError> {
        (&mut self.0).await
    }
}

impl<T> Drop for AbortOnDropHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// snapshot's enabled nicknames as an allowlist.
fn refreshed_enabled_entries(
    config_path: &Path,
    snapshot: &[OnionServiceEntry],
) -> anyhow::Result<Vec<OnionServiceEntry>> {
    let current = Config::read_onion_services(config_path)?;
    Ok(snapshot
        .iter()
        .filter(|entry| entry.enabled)
        .filter_map(|entry| {
            let refreshed = current
                .iter()
                .find(|current| current.nickname == entry.nickname);
            match refreshed {
                Some(current) if current.enabled => Some(current.clone()),
                Some(_) | None => {
                    tracing::warn!(
                        nickname = %entry.nickname,
                        "onion service was removed or disabled during startup; not launched"
                    );
                    None
                }
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use proxy_config::{Config, OnionServiceEntry, OnionServicePort};
    use tor_socks5_onion::keys::{self, NewIdentity};

    fn paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("tor-socks5.ktav");
        let keystore = dir.path().join("keystore");
        (dir, config, keystore)
    }

    fn create_enabled(config: &Path, keystore: &Path, nickname: &str, force: bool) -> String {
        keys::create_service(
            config,
            keystore,
            nickname,
            Some(vec![OnionServicePort {
                onion_port: 80,
                target: "127.0.0.1:8080".to_owned(),
            }]),
            force,
            NewIdentity::Random,
        )
        .expect("create service")
        .address
    }

    fn stored(config: &Path) -> Vec<OnionServiceEntry> {
        Config::read_onion_services(config).expect("read services file")
    }

    #[tokio::test]
    async fn aborting_supervisor_aborts_host_producer() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel::<()>();
        let host = tokio::spawn(async move {
            let _dropped = dropped_tx;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        let (supervisor_ready_tx, supervisor_ready_rx) = tokio::sync::oneshot::channel();
        let supervisor = tokio::spawn(async move {
            let mut host = super::AbortOnDropHandle::new(host);
            let _ = supervisor_ready_tx.send(());
            let _ = host.join().await;
        });

        started_rx.await.expect("host task started");
        supervisor_ready_rx
            .await
            .expect("supervisor owns host handle");
        supervisor.abort();
        let _ = supervisor.await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("aborting the supervisor aborts its host task");
    }

    #[test]
    fn force_during_bootstrap_refreshes_key_and_address_but_not_the_allowlist() {
        let (_dir, config, keystore) = paths();
        let old_address = create_enabled(&config, &keystore, "svc", false);
        let snapshot = stored(&config);

        let new_address = create_enabled(&config, &keystore, "svc", true);
        create_enabled(&config, &keystore, "late", true);
        let current = stored(&config);
        let refreshed =
            super::refreshed_enabled_entries(&config, &snapshot).expect("refresh after bootstrap");

        assert_eq!(refreshed.len(), 1, "only the snapshot name is retained");
        assert_eq!(
            current.len(),
            2,
            "a new enabled service is present in the file"
        );
        assert_eq!(refreshed[0].nickname, "svc");
        assert_ne!(refreshed[0].address.as_deref(), Some(old_address.as_str()));
        assert_eq!(refreshed[0].address.as_deref(), Some(new_address.as_str()));
        let current_service = current
            .iter()
            .find(|entry| entry.nickname == "svc")
            .expect("forced service remains in the file");
        assert_eq!(refreshed[0].key, current_service.key);

        let stale_prepared = keys::prepare_all(Some(&config), &keystore, &snapshot);
        assert_eq!(
            stale_prepared[0].address, None,
            "the old bootstrap identity is rejected by host preparation"
        );

        // Exercise the same public preparation entry point the host uses. The
        // refreshed key must produce the newly recorded address, not the stale
        // bootstrap snapshot's identity.
        let prepared = keys::prepare_all(Some(&config), &keystore, &refreshed);
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].address.as_deref(), Some(new_address.as_str()));
        assert_eq!(prepared[0].entry.key, current_service.key);
    }

    #[test]
    fn remove_during_bootstrap_yields_no_launch_and_keeps_keystore_absent() {
        let (_dir, config, keystore) = paths();
        create_enabled(&config, &keystore, "svc", false);
        let snapshot = stored(&config);

        keys::remove_service(&config, &keystore, "svc").expect("remove service");
        let refreshed =
            super::refreshed_enabled_entries(&config, &snapshot).expect("refresh after bootstrap");
        assert!(refreshed.is_empty(), "removed service is not relaunched");
        assert!(keys::prepare_all(Some(&config), &keystore, &refreshed).is_empty());
        assert!(stored(&config).is_empty());
        let nickname = keys::nickname("svc").expect("valid nickname");
        assert!(keys::identity_file(&keystore, &nickname).is_none());
    }

    #[test]
    fn unchanged_file_keeps_only_snapshot_enabled_nicknames() {
        let (_dir, config, keystore) = paths();
        create_enabled(&config, &keystore, "enabled", false);
        keys::create_service(
            &config,
            &keystore,
            "disabled",
            None,
            false,
            NewIdentity::Random,
        )
        .expect("create disabled service");
        let snapshot = stored(&config);

        let refreshed = super::refreshed_enabled_entries(&config, &snapshot)
            .expect("refresh unchanged services file");

        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].nickname, "enabled");
        assert_eq!(
            refreshed,
            vec![snapshot
                .iter()
                .find(|entry| entry.nickname == "enabled")
                .expect("snapshot contains enabled entry")
                .clone()]
        );
    }

    #[test]
    fn failed_refresh_is_an_error_not_a_stale_snapshot() {
        let (_dir, config, _keystore) = paths();
        let snapshot = vec![OnionServiceEntry {
            nickname: "svc".to_owned(),
            enabled: true,
            address: None,
            key: None,
            circuit_hops: 4,
            bridge_group: None,
            bridges: None,
            ports: vec![OnionServicePort {
                onion_port: 80,
                target: "127.0.0.1:8080".to_owned(),
            }],
        }];
        std::fs::write(Config::onion_path(&config), "services: [ { nickname: [")
            .expect("write invalid file");

        assert!(super::refreshed_enabled_entries(&config, &snapshot).is_err());
    }

    #[test]
    fn keystore_dir_is_arti_native_keystore_under_state() {
        let cfg = Path::new("conf").join("tor-socks5.ktav");
        assert_eq!(
            tor_socks5_runtime::tor_setup::arti_keystore_dir(&cfg),
            Path::new("conf")
                .join("arti-data")
                .join("state")
                .join("keystore")
        );
    }
}
