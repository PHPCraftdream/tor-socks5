//! The marker-based PT child-ownership registry and its pure kill
//! decisions (`pt_reap`), walked through with a fake process table: only
//! own children whose name matches a registered kill marker, or whose
//! `TOR_PT_STATE_LOCATION` exactly equals the batch's token, are ever
//! reap targets. Fully offline; nothing here touches the OS process
//! table.
//!
//! Run with: `cargo run --example pt_reap_decisions -p bridge-verify-core`

use std::collections::HashSet;
use std::path::Path;

use bridge_verify_core::pt_reap::{
    current_markers, environ_state_location, kill_targets, owned_process_targets,
    pt_state_identifier, pt_state_location_token, register_kill_marker, unique_marker_bits,
    KILL_MARKERS_CAP,
};

fn main() {
    let my_pid = std::process::id();
    println!("my pid: {my_pid}");

    // -- Scheme 1: FIFO kill-marker registry (CLI/Windows flow) ----------
    // Per batch the consumer hard-links or copies the PT binary to a
    // uniquely named marker and registers that name; the checks launch
    // the copy, so whatever child the PT manager spawns from it is
    // identifiable by name alone.
    let bits = unique_marker_bits();
    let marker = register_kill_marker(format!("pt-{bits:016x}.exe"));
    println!("registered marker: {marker}");
    println!(
        "registry (process-global FIFO, capped at {KILL_MARKERS_CAP}): {:?}",
        current_markers()
    );

    // Fake process table: (pid, ppid, identifying name). Only 4100 is
    // both our child AND marker-named:
    // - 4101 carries the normal `lyrebird` name: the main engine's PT
    //   child restarted mid-check. Marker-based ownership must never
    //   touch it, however fresh it looks (stability-review section 2);
    // - 4102 is marker-named but belongs to another process (ppid differs):
    //   never touched, full stop.
    let children = [
        (4100, my_pid, marker.as_bytes().to_vec()),
        (4101, my_pid, b"lyrebird".to_vec()),
        (4102, 99_999, marker.as_bytes().to_vec()),
    ];
    let markers: HashSet<Vec<u8>> = current_markers()
        .into_iter()
        .map(String::into_bytes)
        .collect();
    let reap = kill_targets(children.clone(), my_pid, &markers);
    println!("marker scheme reaps: {reap:?} (expected [4100])");

    // Degenerate guard: the copy-failure path (empty registry) kills
    // nothing rather than regressing to guessing.
    let reap = kill_targets(children, my_pid, &HashSet::new());
    println!("empty registry reaps: {reap:?} (expected [])");

    // -- Scheme 2: per-check state-location token (Android flow) --------
    let token = pt_state_location_token(Path::new("check-A"), Path::new("libtorpthelper.so"));
    println!("state-location token: {}", token.display());

    // A child's /proc/<pid>/environ blob carrying the exact token proves
    // ownership; an unreadable environ or a missing key means unproven:
    // fail closed, kill nothing.
    let mut environ = b"HOME=/x\0TOR_PT_STATE_LOCATION=".to_vec();
    environ.extend_from_slice(token.as_os_str().as_encoded_bytes());
    environ.push(0);
    println!(
        "environ carries the token: {}",
        environ_state_location(&environ) == Some(token.as_os_str().as_encoded_bytes())
    );
    println!(
        "environ without the key: {:?} (None = ownership unproven)",
        environ_state_location(b"HOME=/x\0PATH=/bin")
    );

    let candidates = [
        (
            4200,
            my_pid,
            Some(token.as_os_str().as_encoded_bytes().to_vec()),
        ),
        (
            4201,
            my_pid,
            Some(b"/other/pt_state/libtorpthelper.so".to_vec()),
        ),
        (4202, my_pid, None),
    ];
    let reap = owned_process_targets(candidates, my_pid, token.as_os_str().as_encoded_bytes());
    println!("token scheme reaps: {reap:?} (expected [4200])");

    // tor-ptmgr's PT state dir name for a binary: the extension is
    // stripped only when it equals the platform exe extension (`.exe` on
    // Windows, nothing on Android), so the identifier matches what
    // tor-ptmgr itself would derive.
    println!(
        "pt_state_identifier(native/lyrebird.exe) = {}",
        pt_state_identifier(Path::new("native/lyrebird.exe")).display()
    );
}
