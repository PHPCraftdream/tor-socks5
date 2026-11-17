//! Server-run writer slot. The SDK server opens its own `StoreWriter` per
//! run here (`init_run` / `close_run`) and never touches the application's
//! process-global slot (`init_global` / `close_global`). The slot type and
//! race contract are shared with the global slot in `bridge_store_writer.rs`.

use std::path::Path;
use std::sync::Mutex;

use tracing::warn;

use super::{BridgeStore, StoreWriter};

/// Writer slot for one server run. Same contract as the process-global
/// slot: the mutex guards only bookkeeping and is never held across an
/// `.await`; `init_run` spawns only in `Idle` under the lock, `close_run`
/// claims `Active -> Closing`, and the closing task empties the slot as
/// soon as the close completes, so it never references a closed writer.
pub(crate) enum Slot {
    Idle,
    Active(StoreWriter),
    Closing(StoreWriter),
}

static RUN: Mutex<Slot> = Mutex::new(Slot::Idle);

/// Start the run-scoped store writer. Mirrors `init_global`: a second call
/// hands back the existing writer (while a close is finishing, the one
/// being closed), warning when it was opened for a different path.
pub fn init_run(config_path: &Path) -> StoreWriter {
    let resolved = BridgeStore::resolve_path(config_path);
    let mut slot = RUN.lock().unwrap_or_else(|error| error.into_inner());
    let writer = match &*slot {
        Slot::Active(writer) | Slot::Closing(writer) => Some(writer.clone()),
        Slot::Idle => None,
    };
    match writer {
        Some(writer) => {
            if writer.path() != resolved {
                warn!(
                    configured = %resolved.display(),
                    active = %writer.path().display(),
                    "bridge store run writer already started for a different path; keeping the original"
                );
            }
            writer
        }
        None => {
            let writer = StoreWriter::open(config_path);
            *slot = Slot::Active(writer.clone());
            writer
        }
    }
}

/// The run writer, if one exists (live, or still finishing a close).
pub(crate) fn run_current() -> Option<StoreWriter> {
    match &*RUN.lock().unwrap_or_else(|error| error.into_inner()) {
        Slot::Active(writer) | Slot::Closing(writer) => Some(writer.clone()),
        Slot::Idle => None,
    }
}

/// Close the run-scoped store writer at server shutdown. Mirrors
/// `close_global`, with an optional deadline: when the close does not
/// finish in time, the caller gets an error but the spawned close task
/// keeps running and empties the slot when it eventually finishes.
///
/// cancel-safe: yes — the claim is synchronous and the dedicated task
/// always empties the slot, even if this caller is dropped or times out.
pub async fn close_run(deadline: Option<tokio::time::Instant>) -> Option<anyhow::Result<()>> {
    let writer = {
        let mut slot = RUN.lock().unwrap_or_else(|error| error.into_inner());
        let Slot::Active(writer) = &*slot else {
            // Idle: nothing was started (or it already stopped); Closing:
            // another caller owns the in-progress close.
            return None;
        };
        let writer = writer.clone();
        *slot = Slot::Closing(writer.clone());
        writer
    };
    let joined = tokio::spawn(async move {
        let result = writer.close().await;
        let mut slot = RUN.lock().unwrap_or_else(|error| error.into_inner());
        if matches!(&*slot, Slot::Closing(_)) {
            *slot = Slot::Idle;
        }
        result
    });
    // Only the await is deadline-bounded; the spawned close itself is left
    // running and empties the slot when it finishes.
    let joined = match deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline, joined).await {
            Ok(joined) => joined,
            Err(_) => {
                return Some(Err(anyhow::anyhow!(
                    "bridge store writer close did not finish within the deadline; \
                     writer retained in the closing slot"
                )))
            }
        },
        None => joined.await,
    };
    match joined {
        Ok(result) => Some(result),
        Err(join_error) => {
            // The close task died before emptying the slot; release it so a
            // later init can start a fresh writer.
            let mut slot = RUN.lock().unwrap_or_else(|error| error.into_inner());
            if matches!(&*slot, Slot::Closing(_)) {
                *slot = Slot::Idle;
            }
            Some(Err(anyhow::anyhow!(
                "bridge store writer close task panicked: {join_error}"
            )))
        }
    }
}

/// Is the run slot free: no live or closing writer.
#[cfg(any(test, feature = "test-seams"))]
pub fn run_is_idle() -> bool {
    matches!(
        &*RUN.lock().unwrap_or_else(|error| error.into_inner()),
        Slot::Idle
    )
}
