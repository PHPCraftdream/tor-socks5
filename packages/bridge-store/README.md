# bridge-store

Persistent per-bridge health tracking: TCP-probe failure counters, rate-limited failure bumps, latency stamps, and pruning of bridges that fail too often — kept in a plain line-based file next to the active config.

Built for bridge managers that run as more than one process: in the tor-socks5 project a CLI daemon and an Android app both probe bridges, and both want to remember which ones tend to work across restarts. A missing file loads as an empty store; every save publishes atomically (temp file + rename), so a crash mid-save never corrupts the health log.

Health is driven by what this process controls directly — probe-layer reachability. A successful probe resets the failure counter and stamps the latency; a failed probe bumps it at most once per `fail_window` (a burst of retries counts once); once the consecutive-failure counter reaches its limit, the bridge is pruned and returned to the caller, which should also drop it from its config.

## Usage

```rust
use std::time::Duration;
use bridge_line::BridgeLine;
use bridge_store::BridgeStore;

let mut store = BridgeStore::load(path)?; // missing file = empty store
let line: BridgeLine =
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0".parse()?;

let pruned = store.note_probe_round(
    &[line.clone()],                               // probed this round
    &[(line.clone(), Duration::from_millis(234))], // answered: (bridge, latency)
    now, Duration::from_secs(3600), 24, 5,         // timestamp and the limits
);                                                 // returns bridges pruned now
store.save()?;                                     // atomic temp file + rename

let reloaded = BridgeStore::load(path)?;           // observations survive restarts
let best = reloaded.healthiest_bridges(10);        // ranked, healthiest first
```

`health_snapshot` looks up a single bridge's record; `transport_summary` aggregates known/alive/retired counts per transport.

## Example

`cargo run --example health_snapshot` records two probe rounds, saves, reloads, and prints the per-transport summary.
