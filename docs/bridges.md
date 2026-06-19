# Bridges and pluggable transports

On a censored network Tor's public guard relays are blocked, so the proxy
reaches the Tor network through **bridges** with a pluggable transport
(PT). tor-socks5 manages its own bridges end to end: it probes them, orders
them, tracks their health, fetches fresh ones over Tor, and stages
candidates for promotion — both **obfs4** and **webtunnel**, used together.

## Single binary, two modes (busybox dispatch)

The PT runs in-process — there is no second executable to ship. Tor's PT
spec is process-based (`arti`'s `tor-ptmgr` spawns the PT as a child and
talks to it over stdio + a local SOCKS port), but the child can be the
*same* binary. `main()` starts with:

```text
if env has TOR_PT_MANAGED_TRANSPORT_VER  ->  run the lyrebird PT loop
otherwise                                ->  run the SOCKS5 proxy
```

`arti` is pointed at `current_exe()` as the PT binary, so the child is
always our own executable. The bundled Rust lyrebird (from `ptrs-gesher`)
provides both the `obfs4` and `webtunnel` client transports.

## Bridge lines (the working list)

The working bridges live in the main config under `bridges.lines`, one
standard torrc bridge line each. Both transports may be mixed freely:

```ktav
bridges.lines: [
    obfs4 198.51.100.7:9001 FINGERPRINT cert=... iat-mode=0
    webtunnel [2001:db8::1]:443 FINGERPRINT url=https://example.com/path ver=0.0.3
]
```

For webtunnel the `<addr>:<port>` is cosmetic — the real target is the
`url=` host; the probe and the transport both account for this.

## Startup: probe, order, bootstrap

At startup every configured bridge is **probed for reachability** in
parallel (a bounded TCP/TLS handshake; webtunnel resolves the `url=` host).
Dead ones are skipped. The reachable ones — obfs4 and webtunnel together —
are then ordered and handed to arti:

1. **stability** first — the bridge health store keeps a cumulative
   successful-probe count (`seen=N`); more-proven bridges rank higher;
2. **ping** second — ties break by lowest probe latency.

arti tries bridges roughly in list order, so the most reliable and fastest
bridge becomes the first guard it reaches for.

> arti's own state/cache is pinned to an app-local directory
> (`<config-dir>/arti-data/`) so a stale guard sample from a previous run
> can never shadow the configured bridges.

## Health store and lifecycle (`*.alive-bridges.log`)

Probe outcomes are recorded next to the config in
`<stem>.alive-bridges.log`. Per bridge:

```text
# fails=0 seen=12 attempt=<iso> ok=<iso|-> latency=NNms
obfs4 198.51.100.7:9001 FINGERPRINT cert=... iat-mode=0
```

- a **successful** probe resets `fails` to 0, stamps `ok`, and bumps
  `seen` (the stability signal);
- a **failed** probe bumps `fails` — but at most **once per
  `fail_window_mins`** (a burst of retries counts once);
- once `fails` reaches **`max_fails`** the bridge is **pruned** from both
  the store and the config.

This is deliberately gentle — no network flood.

## Fetching fresh bridges: the candidate pool

Fetching bridge lists, probing them, and using them are three decoupled
steps so a huge crowd-sourced list never floods the network:

1. **refresh** — fetch the configured `bridges.sources` over Tor, dedup,
   drop anything already in the working list, and stash the rest in the
   **candidate pool** (`<stem>.candidates.log`). No probing here.
2. **drain** — walk the pool **lazily, one bridge at a time** (short
   timeout, shuffled batch), promote the reachable ones into
   `bridges.lines`, and remove every probed candidate from the pool
   (reachable → promoted, dead → discarded; unprobed stay for next time).
   Because dead entries are dropped, the pool steadily advances across
   drains instead of re-probing a dead head. Needs no Tor — it only
   probes bridges directly.

The startup auto-fetch and the periodic maintenance loop refresh the pool
and drain it to top the working list up to `min_alive`. Both obfs4 and
webtunnel sources are pulled, so the pool — and the working list — grow in
both transports.

## Sources (`bridges.sources`)

Where fresh bridges are fetched from. The minimal form is just a `url`;
`label`, `headers`, and `cookies` are optional, so a collector that needs
an API token or a session cookie can be hit in a custom way:

```ktav
bridges.sources: [
    { url: https://example.com/bridges-obfs4 }
    {
        label: private-collector
        url: https://api.example.org/bridges
        headers: [
            Authorization: Bearer SECRET
        ]
        cookies: [
            session=abc123
        ]
    }
]
```

- `url` — **required**, the HTTPS endpoint.
- `label` — optional, for logs.
- `headers` — optional array of full `Name: Value` lines.
- `cookies` — optional array of `name=value` pairs, folded into one
  `Cookie:` header.

Header/cookie values are stripped of CR/LF to prevent header injection.

## The `bridges fetch` command

Manually refresh the pool and promote reachable newcomers:

```bash
tor-socks5 bridges fetch                 # refresh pool, promote up to 10
tor-socks5 bridges fetch --count 25      # promote up to 25 reachable
tor-socks5 bridges fetch --dry-run       # refresh pool only, don't promote
tor-socks5 bridges fetch --no-probe      # fill the pool, skip probing
tor-socks5 bridges fetch --timeout-secs 45
```

It bootstraps Tor on the existing bridges (or built-in seeds), refreshes
the pool from the sources, then lazily probes and promotes up to `--count`.

## Configuration knobs (`bridges.*`)

| Key | Default | Meaning |
|-----|---------|---------|
| `lines` | `[]` | Working bridge lines (obfs4 / webtunnel). |
| `sources` | 3 built-in | HTTPS collectors to fetch from (see above). |
| `use_seeds` | `true` | Fall back to bundled seed bridges (`*.seeds`) when no configured bridge is reachable at startup. |
| `auto_fetch` | `true` | Refresh + drain in the background to keep the working list healthy. |
| `min_alive` | `2` | Target number of healthy working bridges; top up below this. |
| `max_body_mib` | `64` | Max size of a single fetched source response. |
| `max_fails` | `24` | Prune a bridge after this many failed probes. |
| `fail_window_mins` | `60` | A bridge's failure counter bumps at most once per this window. |
| `recheck_interval_mins` | `60` | How often the maintenance loop re-probes, refreshes, and drains. `0` disables it. |

## State files (next to the config, all gitignored)

- `<stem>.alive-bridges.log` — bridge health store (`fails`, `seen`, `ok`,
  latency).
- `<stem>.candidates.log` — unverified candidate pool.
- `arti-data/` — arti's pinned state + cache directory.
- `<stem>.seeds` — optional bundled seed bridges (never committed).
