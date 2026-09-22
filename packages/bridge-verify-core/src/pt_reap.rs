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

/// Mirrors tor-ptmgr 0.43.0's `pt_identifier_as_path` (tor-ptmgr-0.43.0/src/
/// managed.rs): take the file name, strip the extension iff it equals
/// `EXE_EXTENSION` case-insensitively (on Windows "lyrebird.exe" becomes
/// "lyrebird"; on Android `EXE_EXTENSION` is "" so "libtorpthelper.so" stays
/// whole). No file name (e.g. "/" or "") yields an empty `PathBuf`: tor-ptmgr
/// itself refuses to spawn such a binary (`PtError::NotAFile`), so that
/// degenerate token is never used to kill anything.
pub fn pt_state_identifier(binary_path: &std::path::Path) -> std::path::PathBuf {
    let Some(file_name) = binary_path.file_name() else {
        return std::path::PathBuf::new();
    };
    let mut identifier = std::path::PathBuf::from(file_name);
    let exe_ext = std::env::consts::EXE_EXTENSION;
    let matches_exe_ext = identifier
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(exe_ext));
    if matches_exe_ext {
        identifier.set_extension("");
    }
    identifier
}

/// The exact `TOR_PT_STATE_LOCATION` value tor-ptmgr 0.43.0 passes the PT
/// child for one throwaway bridge check, computed the same way its stack
/// does: arti-wrapper's `build_config` appends "state" to
/// `Settings.state_dir` (the check dir); arti-client 0.43 appends "pt_state"
/// (arti-client-0.43.0/src/client.rs); tor-ptmgr 0.43 appends the binary
/// identifier (see [`pt_state_identifier`]) and passes the result verbatim as
/// `TOR_PT_STATE_LOCATION` (tor-ptmgr-0.43.0/src/ipc.rs). Because the check
/// dir is unique per check, the result is a unique per-check ownership token.
/// Assumption: these are app-private paths carrying no CfgPath variable
/// syntax, so the lossy string round-trip of the path is the identity. A
/// consumer may use this value as an exact-byte ownership token compared
/// against bytes from `/proc/<pid>/environ`.
pub fn pt_state_location_token(
    check_state_dir: &std::path::Path,
    pt_binary: &std::path::Path,
) -> std::path::PathBuf {
    check_state_dir
        .join("state")
        .join("pt_state")
        .join(pt_state_identifier(pt_binary))
}

/// The key parsed out of a raw /proc/<pid>/environ blob.
const STATE_LOCATION_KEY: &[u8] = b"TOR_PT_STATE_LOCATION";

/// Extracts the `TOR_PT_STATE_LOCATION` value from a raw
/// `/proc/<pid>/environ` byte blob (entries separated by b'\0', each
/// `KEY=VALUE` split at the FIRST b'='). Returns the value bytes of the
/// FIRST matching entry, or None when absent. An unreadable/empty environ
/// (zombie, vanished process) also yields None, and callers must treat None
/// as "ownership unproven -- do not kill": fail closed.
pub fn environ_state_location(environ: &[u8]) -> Option<&[u8]> {
    environ.split(|byte| *byte == 0).find_map(|entry| {
        let eq = entry.iter().position(|byte| *byte == b'=')?;
        let (key, value) = (&entry[..eq], &entry[eq + 1..]);
        (key == STATE_LOCATION_KEY).then_some(value)
    })
}

/// Pure kill decision for the state-location ownership scheme: the per-check
/// token analogue of [`kill_targets`] for the Android verify flow, which can
/// no longer use a marker-name scheme (Android W^X forbids executing a
/// copied PT binary in scratch, and a global marker registry would let one
/// verification batch kill another's children). Each child yields
/// `(pid, ppid, Option<state_location_bytes>)` where the Option is the
/// parsed [`environ_state_location`] value (None = unproven). A pid is a
/// kill target iff ALL hold:
/// - `token` non-empty: an empty token kills nothing (fail closed).
/// - `ppid == my_pid`: only ever our own direct children.
/// - `pid != my_pid`: never target ourselves.
/// - `pid != 0`: pid 0 is the kernel (kill(2) semantics: process group 0 /
///   calling group), never a child -- exclude it defensively.
/// - state_location is Some and equals `token` by EXACT full-byte equality
///   -- never prefix, never suffix: a sibling directory `.../pt_state0/...`
///   or a longer path sharing the token as a prefix must NOT match.
///
/// Recycled-PID contract: callers re-read environ at kill time, so a
/// recycled PID whose environ no longer carries the token is rejected.
pub fn owned_process_targets(
    children: impl IntoIterator<Item = (u32, u32, Option<Vec<u8>>)>,
    my_pid: u32,
    token: &[u8],
) -> Vec<u32> {
    if token.is_empty() {
        return Vec::new();
    }
    children
        .into_iter()
        .filter(|(pid, ppid, state_location)| {
            *ppid == my_pid
                && *pid != my_pid
                && *pid != 0
                && state_location.as_deref() == Some(token)
        })
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

    // -- State-location ownership scheme (Android verify flow) --

    #[test]
    fn pt_state_identifier_keeps_android_so_suffix() {
        // "so" never equals EXE_EXTENSION ("" on unix, "exe" on windows),
        // so the identifier keeps the full file name on ALL platforms.
        let path = std::path::Path::new("/x/libtorpthelper.so");
        assert_eq!(
            pt_state_identifier(path),
            std::path::PathBuf::from("libtorpthelper.so")
        );
    }

    #[cfg(windows)]
    #[test]
    fn pt_state_identifier_strips_exe_on_windows() {
        assert_eq!(
            pt_state_identifier(std::path::Path::new("C:/x/lyrebird.exe")),
            std::path::PathBuf::from("lyrebird")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn pt_state_identifier_keeps_exe_off_windows() {
        // Documents platform parity with tor-ptmgr's EXE_EXTENSION rule:
        // off Windows the ".exe" extension is not the exe extension, so it
        // stays.
        assert_eq!(
            pt_state_identifier(std::path::Path::new("/x/lyrebird.exe")),
            std::path::PathBuf::from("lyrebird.exe")
        );
    }

    #[test]
    fn pt_state_location_token_composes_state_and_pt_state() {
        // Portable composition: relative inputs keep Path::join well-formed
        // on every host platform.
        let token = pt_state_location_token(
            std::path::Path::new("check-A"),
            std::path::Path::new("native/libtorpthelper.so"),
        );
        assert_eq!(
            token,
            std::path::PathBuf::from("check-A")
                .join("state")
                .join("pt_state")
                .join("libtorpthelper.so")
        );
        // Degenerate identifier: a binary with no file name joins nothing,
        // so the token is exactly base/state/pt_state. (tor-ptmgr refuses to
        // spawn such a binary, so this token never kills.)
        let degenerate =
            pt_state_location_token(std::path::Path::new("check-A"), std::path::Path::new("/"));
        assert_eq!(
            degenerate,
            std::path::PathBuf::from("check-A")
                .join("state")
                .join("pt_state")
        );
    }

    #[test]
    fn environ_state_location_finds_value() {
        assert_eq!(
            environ_state_location(
                b"HOME=/x\0TOR_PT_STATE_LOCATION=/check/state/pt_state/lib.so\0"
            ),
            Some(b"/check/state/pt_state/lib.so".as_slice())
        );
    }

    #[test]
    fn environ_state_location_absent() {
        assert_eq!(environ_state_location(b"HOME=/x\0PATH=/bin"), None);
    }

    #[test]
    fn environ_state_location_entry_without_equals_is_skipped() {
        assert_eq!(
            environ_state_location(b"NOVALUE\0TOR_PT_STATE_LOCATION=/v"),
            Some(&b"/v"[..])
        );
    }

    #[test]
    fn environ_state_location_empty_slice_is_none() {
        assert_eq!(environ_state_location(b""), None);
    }

    #[test]
    fn environ_state_location_first_match_wins() {
        assert_eq!(
            environ_state_location(b"TOR_PT_STATE_LOCATION=/first\0TOR_PT_STATE_LOCATION=/second"),
            Some(b"/first".as_slice())
        );
    }

    #[test]
    fn environ_state_location_value_may_contain_equals() {
        // Split at the FIRST '=' only.
        assert_eq!(
            environ_state_location(b"TOR_PT_STATE_LOCATION=/a=b/c"),
            Some(b"/a=b/c".as_slice())
        );
    }

    #[test]
    fn environ_state_location_key_match_is_exact_case() {
        assert_eq!(environ_state_location(b"tor_pt_state_location=/v"), None);
    }

    fn token() -> Vec<u8> {
        pt_state_location_token(
            std::path::Path::new("check-A"),
            std::path::Path::new("libtorpthelper.so"),
        )
        .into_os_string()
        .into_encoded_bytes()
    }

    #[test]
    fn owned_targets_kill_exact_token_child() {
        let tok = token();
        let children = [
            (80u32, 7u32, Some(tok.clone())),
            (81, 7, Some(b"/other/pt_state/libtorpthelper.so".to_vec())),
        ];
        assert_eq!(owned_process_targets(children, 7, &tok), vec![80]);
    }

    #[test]
    fn owned_targets_spare_main_engine_location() {
        // Main-engine-style location (abstract placeholder package path) is
        // a different path, so never a target.
        let tok = token();
        let children = [(
            80,
            7,
            Some(
                b"/data/data/app.placeholder/files/tor/arti-data/state/pt_state/libtorpthelper.so"
                    .to_vec(),
            ),
        )];
        assert!(owned_process_targets(children, 7, &tok).is_empty());
    }

    #[test]
    fn owned_targets_spare_another_batchs_children() {
        // A concurrent batch's check dir yields a different token: its
        // children are exact non-matches.
        let tok = token();
        let other = pt_state_location_token(
            std::path::Path::new("check-B"),
            std::path::Path::new("libtorpthelper.so"),
        )
        .into_os_string()
        .into_encoded_bytes();
        let children = [(80, 7, Some(other))];
        assert!(owned_process_targets(children, 7, &tok).is_empty());
    }

    #[test]
    fn owned_targets_reject_prefix_and_sibling_matches() {
        // Exact full-byte equality only: a token-suffixed longer path and a
        // sibling directory (one extra char) must both be rejected.
        let tok = token();
        let mut prefix = tok.clone();
        prefix.extend_from_slice(b"/x");
        let mut sibling_dir = tok.clone();
        // .../pt_state/libtorpthelper.so -> .../pt_state2/libtorpthelper.so
        let last = sibling_dir.len() - "libtorpthelper.so".len();
        sibling_dir.insert(last - 1, b'2');
        let children = [(80, 7, Some(prefix)), (81, 7, Some(sibling_dir))];
        assert!(owned_process_targets(children, 7, &tok).is_empty());
    }

    #[test]
    fn owned_targets_spare_unproven_and_different_children() {
        let tok = token();
        let children = [
            (80, 7, None), // recycled PID / unreadable environ: fail closed
            (81, 7, Some(b"/somewhere/else".to_vec())),
        ];
        assert!(owned_process_targets(children, 7, &tok).is_empty());
    }

    #[test]
    fn owned_targets_spare_non_children_and_self() {
        let tok = token();
        let children = [
            (80, 8, Some(tok.clone())), // not our child
            (7, 7, Some(tok.clone())),  // ourselves
        ];
        assert!(owned_process_targets(children, 7, &tok).is_empty());
    }

    #[test]
    fn owned_targets_spares_pid_zero() {
        // pid 0 is the kernel, never a child; exclude it defensively.
        let tok = token();
        let children = [(0u32, 7u32, Some(tok.clone()))];
        assert!(owned_process_targets(children, 7, &tok).is_empty());
    }

    #[test]
    fn owned_targets_empty_token_kills_nothing() {
        // Fail closed: an empty (degenerate) token never kills, even for an
        // exact-looking child.
        let children = [(80, 7, Some(Vec::new()))];
        assert!(owned_process_targets(children, 7, b"").is_empty());
    }
}
