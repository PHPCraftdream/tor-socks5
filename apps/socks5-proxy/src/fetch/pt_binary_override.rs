/// Pure decision function: extract PT binary path from an optional env var value.
/// Returns `None` for `None` or empty `OsStr`; `Some(PathBuf)` for non-empty values.
/// This is testable without touching process state.
pub(super) fn pt_binary_override_from(
    value: Option<&std::ffi::OsStr>,
) -> Option<std::path::PathBuf> {
    match value {
        Some(v) if !v.is_empty() => Some(std::path::PathBuf::from(v)),
        _ => None,
    }
}
