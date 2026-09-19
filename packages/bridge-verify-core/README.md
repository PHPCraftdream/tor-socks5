# bridge-verify-core

Shared support logic for Tor bridge verification, extracted from two line-by-line-identical copies that lived in the tor-socks5 CLI daemon and its Android JNI engine. Two pieces:

- `snapshot` — consistent SQLite cache-dir snapshotting for a throwaway check client;
- `pt_reap` — a marker-based pluggable-transport child-ownership registry and the pure kill decisions behind leak-reaping sweeps.

The second answers a sharp question: when a periodic bridge check launches a pluggable transport (lyrebird, webtunnel) and is then cancelled or times out, which leftover child processes may be killed? The answer never depends on guessing. Only own children whose image name matches a registered kill marker — or whose `TOR_PT_STATE_LOCATION` exactly equals the batch's state-location token — are ever reap targets. Everything else fails closed and kills nothing: another process's marker-named child, the main engine's live `lyrebird`, an unreadable environ, a missing registry.

## Usage

`pt_reap` is offline and pure: feed it a process table, get kill decisions.

```rust
use std::collections::HashSet;
use bridge_verify_core::pt_reap::{
    current_markers, kill_targets, register_kill_marker, unique_marker_bits,
};

let marker = register_kill_marker(format!("pt-{:016x}.exe", unique_marker_bits()));
let markers: HashSet<Vec<u8>> =
    current_markers().into_iter().map(String::into_bytes).collect();
let my_pid = std::process::id();

// Fake process table: (pid, ppid, image name).
// Only 4100 is both our child AND marker-named.
let children = [
    (4100, my_pid, marker.as_bytes().to_vec()),
    (4101, my_pid, b"lyrebird".to_vec()),
    (4102, 99_999, marker.as_bytes().to_vec()),
];
let reap = kill_targets(children, my_pid, &markers); // [4100]
```

Platform-specific parts — the Win32 Toolhelp32 snapshot and `TerminateProcess` sweep, the Android `/proc` snapshot and `kill(2)` sweep, marker-file creation — stay in the consumers as thin adapters; this crate holds the invariants.

## Example

`cargo run --example pt_reap_decisions` walks both ownership schemes (kill-marker registry and state-location token) with a fake process table.
