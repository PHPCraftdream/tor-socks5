//! Bind once per configured address; only local availability failures are skippable.

use std::io::{self, ErrorKind};

use anyhow::{bail, Context, Result};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Debug)]
pub(super) struct SkippedListener {
    pub(super) address: String,
    pub(super) error: io::Error,
}

#[derive(Debug)]
pub(super) struct BoundListeners {
    pub(super) listeners: Vec<TcpListener>,
    pub(super) skipped: Vec<SkippedListener>,
}

fn skippable(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::AddrInUse | ErrorKind::PermissionDenied | ErrorKind::AddrNotAvailable
    )
}

/// cancel-safe: yes — cancellation at bind drops all listeners owned here;
/// no retries, socket-option changes, or external state mutations.
pub(super) async fn bind_listeners(addresses: &[String]) -> Result<BoundListeners> {
    if addresses.is_empty() {
        info!(
            bound = 0,
            skipped = 0,
            bound_addresses = ?Vec::<String>::new(),
            skipped_addresses = ?Vec::<String>::new(),
            "SOCKS5 listener binding summary"
        );
        bail!(
            "no listen addresses configured — set `listen` in the config \
             (a single address or a list); addresses/reasons: []"
        );
    }
    let mut bound = BoundListeners {
        listeners: Vec::with_capacity(addresses.len()),
        skipped: Vec::new(),
    };
    for address in addresses {
        match TcpListener::bind(address).await {
            Ok(listener) => {
                info!(listen_addr = %address, "SOCKS5 proxy is listening");
                bound.listeners.push(listener);
            }
            Err(error) if skippable(error.kind()) => {
                warn!(listen_addr = %address, kind = ?error.kind(),
                    raw_os_error = ?error.raw_os_error(), %error,
                    "skipping SOCKS5 listen address");
                bound.skipped.push(SkippedListener {
                    address: address.clone(),
                    error,
                });
            }
            Err(error) => return Err(error).with_context(|| format!("failed to bind {address}")),
        }
    }
    let bound_addresses = bound
        .listeners
        .iter()
        .map(|listener| {
            listener
                .local_addr()
                .map(|address| address.to_string())
                .unwrap_or_else(|error| format!("local endpoint unavailable: {error}"))
        })
        .collect::<Vec<_>>();
    let skipped_addresses = bound
        .skipped
        .iter()
        .map(|skip| format!("{}: {:?}: {}", skip.address, skip.error.kind(), skip.error))
        .collect::<Vec<_>>();
    info!(
        bound = bound.listeners.len(),
        skipped = bound.skipped.len(),
        bound_addresses = ?bound_addresses,
        skipped_addresses = ?skipped_addresses,
        "SOCKS5 listener binding summary"
    );
    if bound.listeners.is_empty() {
        let reasons = bound
            .skipped
            .iter()
            .map(|skip| format!("{}: {:?}: {}", skip.address, skip.error.kind(), skip.error))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("no SOCKS5 listen addresses could be bound — addresses/reasons: [{reasons}]");
    }
    Ok(bound)
}

#[path = "retry.rs"]
pub(super) mod retry;

#[cfg(test)]
#[path = "server_binding_tests.rs"]
mod tests;
