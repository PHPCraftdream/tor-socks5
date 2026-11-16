//! Thin shell over the library's onion-service host
//! (`tor_socks5_onion::host`): filter the enabled services and hand them,
//! the keystore directory and the config path to the host. The launch
//! choreography, the launch logs, the keystore lock and the status snapshot
//! all live in the library crate.

use std::path::{Path, PathBuf};

use proxy_config::OnionServiceEntry;
use tokio_util::sync::CancellationToken;

use tor_socks5_onion::host::OnionHostConfig;
use tor_socks5_runtime::tor_watchdog::TorHandle;

/// Same base as the running server: `tor_setup::arti_base_dir` is what the
/// binary's `commands/onion/store.rs` computes too, so the CLI tools and the
/// server resolve the same keystore.
fn keystore_dir(config_path: Option<&Path>) -> PathBuf {
    tor_socks5_runtime::tor_setup::arti_base_dir(config_path)
}

/// Spawn the onion-service host producer if any configured service is
/// enabled. Appends the producer's join handle to `producers` (cancelled and
/// joined by the server's regular shutdown choreography). No-op when nothing
/// is enabled: default configs keep today's behavior exactly.
///
/// The "starting configured onion services" info line (and the soft-limit
/// warning) now live in the library's `start()`; this shell logs nothing.
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
    let host_config = OnionHostConfig::new(handle, keystore_dir(config_path), token)
        .with_entries(enabled)
        .with_config_path(config_path.map(Path::to_path_buf));
    producers.push(
        tor_socks5_onion::host::OnionHost::new(host_config)
            .start()
            .detach(),
    );
}
