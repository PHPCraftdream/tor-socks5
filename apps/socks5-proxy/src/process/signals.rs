//! Graceful-stop signal handling.
//!
//! [`wait_for_signal`] resolves on the first Ctrl+C (and on Windows also
//! on Ctrl+Break). The caller uses it in a `tokio::select!` to break
//! out of the accept loop. Combined with explicit `drop` of the
//! `TorTunnel` it lets arti tear PTs down cleanly and release its
//! state-directory lock — so the *next* run doesn't see "another
//! instance has the lock".

/// Resolve when the user asks us to stop. Returns the human-readable name
/// of the signal observed.
#[cfg(windows)]
pub async fn wait_for_signal() -> &'static str {
    use tokio::signal::windows::{ctrl_break, ctrl_c};
    let mut c_c = match ctrl_c() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not register Ctrl+C handler — falling back to no signal");
            std::future::pending::<()>().await;
            unreachable!();
        }
    };
    let mut c_break = match ctrl_break() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not register Ctrl+Break handler");
            // We still want Ctrl+C to work.
            c_c.recv().await;
            return "Ctrl+C";
        }
    };

    tokio::select! {
        _ = c_c.recv() => "Ctrl+C",
        _ = c_break.recv() => "Ctrl+Break",
    }
}

#[cfg(not(windows))]
pub async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not register SIGINT handler");
            std::future::pending::<()>().await;
            unreachable!();
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not register SIGTERM handler");
            sigint.recv().await;
            return "SIGINT";
        }
    };
    tokio::select! {
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    }
}
