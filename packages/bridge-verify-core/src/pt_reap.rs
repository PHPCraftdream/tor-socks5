//! Marker-based PT child ownership: the FIFO kill-marker registry shared by
//! the CLI daemon's and Android engine's leak-reaping sweeps, plus the pure
//! kill decision both used to duplicate.
//!
//! Reaps the PT processes a throwaway verify client's arti client leaves
//! running -- nothing short of an explicit kill reliably stops them, because
//! `tor-ptmgr`'s graceful-shutdown thread blocks in a synchronous read of the
//! child's stdout. Ownership is marker-based, not time-of-appearance-based:
//! per batch the consumer creates a uniquely named executable copy of the PT
//! binary (hard link where possible, copy otherwise) and registers its file
//! name via [`register_kill_marker`]; the checks are launched with that copy
//! as their PT binary, so whatever child the PT manager spawns from it is
//! identifiable by name alone, and the post-check sweep kills only own
//! children whose name matches a registered marker via [`kill_targets`].
//! A restarted main-engine PT child carries the normal binary name and can
//! never match a marker. See `docs/stability-review-2026-09-08.md` section 2.
//!
//! The registry never shrinks mid-process so children that escaped their own
//! call's kill keep getting reaped by later calls (capped at
//! [`KILL_MARKERS_CAP`] names, FIFO). Marker-file creation (Windows exe-name
//! format + hard-link/copy, Android 48-bit-masked `comm`-sized name +
//! `create_dir_all` + chmod) stays in the consumers; only the counter, the
//! registry, and the decision are shared here.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// FIFO registry of marker file names that identify "our" PT children.
/// Never shrinks per-check: a leaked child that escaped its own call's
/// kill sweep keeps matching (and gets reaped) on every later call.
static KILL_MARKERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Distinguishes markers created within the same nanosecond tick.
static MARKER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 128 registered names is far beyond anything a long-lived service can
/// accumulate (each batch adds at most one); the cap just guarantees the
/// registry cannot grow without bound over a multi-day process.
pub const KILL_MARKERS_CAP: usize = 128;

/// Raw uniqueness input for a new marker name: nanos-since-epoch XOR pid
/// (shifted) XOR the per-call counter (fetched-and-incremented exactly once
/// per marker). Consumers format this into their platform's name (Windows
/// `pt-{:016x}.exe`; Android masked to 48 bits and `pt-{:012x}` so the name
/// is exactly `TASK_COMM_LEN - 1` bytes).
pub fn unique_marker_bits() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (u64::from(std::process::id()) << 32))
        ^ MARKER_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Registers `marker_name` in the FIFO kill-marker registry and returns it.
/// Duplicate names are ignored (the first registration wins); exceeding
/// [`KILL_MARKERS_CAP`] evicts the oldest name.
pub fn register_kill_marker(marker_name: String) -> String {
    let mut markers = KILL_MARKERS.lock().unwrap_or_else(|error| {
        KILL_MARKERS.clear_poison();
        error.into_inner()
    });
    if !markers.contains(&marker_name) {
        markers.push(marker_name.clone());
        if markers.len() > KILL_MARKERS_CAP {
            markers.remove(0); // FIFO eviction of the oldest name
        }
    }
    marker_name
}

/// Snapshot of the currently registered marker names.
pub fn current_markers() -> HashSet<String> {
    let markers = KILL_MARKERS.lock().unwrap_or_else(|error| {
        KILL_MARKERS.clear_poison();
        error.into_inner()
    });
    markers.iter().cloned().collect()
}

/// Pure decision core of both platforms' kill sweeps, kept free of OS APIs
/// for testability. `children` yields `(pid, ppid, name_bytes)` triples where
/// `name_bytes` is each child's identifying name (Windows: lowercased exe
/// file name; Android: the first 15 `comm` bytes) and `markers` holds the
/// correspondingly normalized registered marker names (Windows callers
/// lowercase the stored names; since marker names are generated lowercase
/// ASCII this preserves the historical case-insensitive Windows match;
/// Android callers pass marker-name bytes truncated to 15, preserving exact
/// `comm` matching). Guards, in order:
/// - empty `markers`: kill nothing -- the copy-failure degenerate path must
///   never regress to guessing (a diff-based fallback would kill collateral).
/// - `ppid == my_pid`: only ever touch our own children -- never another
///   process's children, however marker-named. (The Windows caller's
///   snapshot already filters to own children; it passes `my_pid` as each
///   child's ppid.)
/// - `pid != my_pid`: never target ourselves.
/// - name in `markers`: only marker-named children, by exact byte equality
///   after caller-side normalization. Deliberately name-verified, NOT
///   time-of-appearance-verified: the main engine's PT child -- however
///   freshly restarted -- carries the normal binary name and can never match
///   a marker. See docs/stability-review-2026-09-08.md section 2.
pub fn kill_targets(
    children: impl IntoIterator<Item = (u32, u32, Vec<u8>)>,
    my_pid: u32,
    markers: &HashSet<Vec<u8>>,
) -> Vec<u32> {
    if markers.is_empty() {
        return Vec::new();
    }
    children
        .into_iter()
        .filter(|(pid, ppid, name)| *ppid == my_pid && *pid != my_pid && markers.contains(name))
        .map(|(pid, _, _)| pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Scenario moves: Android side (jni_verify.rs `reap_targets` tests) --

    const MARKER: &str = "pt-0123456789ab";

    fn markers() -> HashSet<Vec<u8>> {
        HashSet::from([MARKER.as_bytes().to_vec()])
    }

    /// The stability-review section 2 scenario: the main engine's PT restarted
    /// mid-check (brand-new pid, normal binary name, no marker). The old
    /// baseline-diff killed exactly this child; marker-based ownership makes
    /// that impossible regardless of how "new" it is.
    #[test]
    fn kill_targets_spares_restarted_main_pt_android() {
        let children = [(80, 7, b"libtorpthelper".to_vec())];
        assert!(kill_targets(children, 7, &markers()).is_empty());
    }

    #[test]
    fn kill_targets_kills_only_marker_named_children_android() {
        let children = [
            (80, 7, MARKER.as_bytes().to_vec()),
            (81, 7, b"libtorpthelper".to_vec()),
            (82, 7, b"somethingelse".to_vec()),
        ];
        assert_eq!(kill_targets(children, 7, &markers()), vec![80]);
    }

    #[test]
    fn kill_targets_spares_non_children_android() {
        // Marker-named but not our child: never touched, full stop.
        let children = [(80, 8, MARKER.as_bytes().to_vec())];
        assert!(kill_targets(children, 7, &markers()).is_empty());
    }

    #[test]
    fn kill_targets_never_targets_self_android() {
        let my_pid = std::process::id();
        let children = [(my_pid, 1, MARKER.as_bytes().to_vec())];
        assert!(kill_targets(children, my_pid, &markers()).is_empty());
    }

    #[test]
    fn kill_targets_empty_registry_kills_nothing_android() {
        // The copy-failure degenerate path never kills: no regression to guessing.
        let children = [(80, 7, MARKER.as_bytes().to_vec())];
        assert!(kill_targets(children, 7, &HashSet::new()).is_empty());
    }

    // -- Scenario moves: CLI side (bridge_verifier.rs `kill_targets` tests) --

    const CLI_MARKER: &str = "pt-abcdef0123456789.exe";

    fn cli_markers() -> HashSet<Vec<u8>> {
        // Windows adapter normalization: marker names lowercased to bytes.
        HashSet::from([CLI_MARKER.to_ascii_lowercase().into_bytes()])
    }

    /// The P1 regression pin (stability review 2026-09-08 §2): a child with
    /// the NORMAL exe name — i.e. the main engine's PT restarted mid-check —
    /// must never be a kill target, no matter how "new" it looks.
    #[test]
    fn kill_targets_spares_restarted_main_pt_child_cli() {
        let my_pid = std::process::id();
        let targets = kill_targets(
            vec![(
                1001,
                my_pid,
                b"socks5-proxy.exe".to_ascii_lowercase().to_vec(),
            )],
            my_pid,
            &cli_markers(),
        );
        assert!(!targets.contains(&1001));
        assert!(targets.is_empty());
    }

    #[test]
    fn kill_targets_kills_only_marker_named_children_cli() {
        let my_pid = std::process::id();
        let targets = kill_targets(
            vec![
                (1002, my_pid, CLI_MARKER.to_ascii_lowercase().into_bytes()),
                (1003, my_pid, b"unrelated.exe".to_ascii_lowercase().to_vec()),
            ],
            my_pid,
            &cli_markers(),
        );
        assert_eq!(targets, vec![1002]);
    }

    #[test]
    fn kill_targets_empty_registry_kills_nothing_cli() {
        // The copy-failure degenerate path never kills.
        let my_pid = std::process::id();
        let targets = kill_targets(
            vec![(1004, my_pid, CLI_MARKER.to_ascii_lowercase().into_bytes())],
            my_pid,
            &HashSet::new(),
        );
        assert!(targets.is_empty());
    }

    #[test]
    fn kill_targets_never_targets_self_cli() {
        let my_pid = std::process::id();
        let targets = kill_targets(
            vec![(my_pid, my_pid, CLI_MARKER.to_ascii_lowercase().into_bytes())],
            my_pid,
            &cli_markers(),
        );
        assert!(targets.is_empty());
    }
}
