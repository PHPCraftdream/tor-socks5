# bridge-probe

Parallel TCP reachability probing and latency ranking for Tor bridge lines, plus the DNS plumbing bridges actually need: portable `DnsHint` records, a built-in multi-provider DoH pool, and webtunnel hostname extraction.

Made for bridge managers facing the cold-start problem: arti's guard manager walks configured bridges one at a time with long back-offs, which is miserable when half the list is dead. This crate probes every bridge concurrently (bounded in-flight attempts), then hands back the live ones sorted by latency, fastest first — so the first connection attempt lands on a bridge that answers.

Transport-aware: for most transports the probe target is the bridge's `addr`, but webtunnel hides its real endpoint in the `url=` parameter (with an optional `addr=` override), and the probe resolves and connects accordingly. Bridges a round could not actually test — resolver outage, DNS down — come back as `unmeasured`, not as failures; callers that track health need that difference.

## Usage

```rust
use bridge_line::BridgeLine;
use bridge_probe::probe_and_sort;

let bridges: Vec<BridgeLine> = lines
    .iter()
    .map(|s| s.parse().expect("valid bridge line"))
    .collect();
// Live bridges as (bridge, latency) pairs, fastest first.
let alive = probe_and_sort(bridges, std::time::Duration::from_secs(10)).await;
```

(The crate's tokio features enable `rt`, not `rt-multi-thread` — a current-thread runtime is enough.) For DNS, `format_dns_hint_line`/`parse_dns_hint_line` round-trip shareable `(host, addrs, resolved_at)` facts, `seed_disk_fallback` imports them, `best_known_answer` reads the best known answer without ever resolving, and `resolve_addrs` resolves live through the DoH pool — total provider failure is an `Err`, never a panic.

## Example

`cargo run --example dns_lookup` covers both DNS sides: offline hint import/readback and live DoH resolution.
