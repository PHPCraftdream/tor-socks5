use crate::{BootstrapEvent, BootstrapEventCallback};

/// Map one `BootstrapStatus` to callback event(s). Returns `true` when
/// the status is ready for traffic (the subscriber's terminal success —
/// the forwarding task exits after emitting `Ready`).
pub(crate) fn emit_bootstrap_event(
    status: &arti_client::status::BootstrapStatus,
    on_event: &BootstrapEventCallback,
) -> bool {
    if status.ready_for_traffic() {
        on_event(BootstrapEvent::Ready);
        true
    } else {
        on_event(BootstrapEvent::Progress(
            status.as_frac(),
            status.to_string(),
        ));
        if let Some(blockage) = status.blocked() {
            on_event(BootstrapEvent::Blocked(blockage.to_string()));
        }
        false
    }
}
