# Local DNS server (DoH through Tor)

`tor-socks5` can run an optional (default OFF) local DNS server. Clients send ordinary
UDP/TCP DNS queries; each is answered through a pool of public DNS-over-HTTPS (DoH)
providers, and every DoH request itself is tunnelled through the already-established
Tor connection — a hostname never leaves the machine as plaintext DNS. Under censorship
this defeats DNS blocking and tampering: to an observer the resolution is indistinguishable
from ordinary Tor traffic.

The feature requires the Tor egress. Combined with an upstream SOCKS5 proxy it is a
fail-fast startup error (refusing to start beats silently leaking plaintext queries):

```
dns_server.enabled requires Tor egress, not an upstream SOCKS5 proxy — disable dns_server or remove the upstream
```

## Configuration

```ktav
dns_server.enabled: true
## local host:port binds; one UDP+TCP listener pair per address
## default 127.0.0.1:15353 — deliberately not 53, a privileged port
dns_server.listen: [
    127.0.0.1:15353
]
## drop the built-in provider list; the pool becomes the custom entries only
dns_server.disable_builtin_providers: false
## operator-added DoH providers, merged after the built-ins
dns_server.custom_doh_providers: [
    {
        ip: 9.9.9.9
        hostname: dns.quad9.net
        path: /dns-query
    }
]
```

- `dns_server.listen` and the SOCKS5/HTTP CONNECT `listen` option both accept
  a scalar string or a list. Each scalar/list entry also accepts comma shorthand
  `host1,host2:port`: `dns_server.listen: 127.0.0.1,[::1]:15353` expands to
  `127.0.0.1:15353` and `[::1]:15353`. IPv6 hosts must be bracketed.
  The equivalent proxy example is `listen: 127.0.0.1,[::1]:1080`.
  Expansion deduplicates addresses in order, keeping the first occurrence;
  config writeback uses the expanded list for both options.
- `ip` — the IPv4/IPv6 literal the DoH TCP connection is opened to **through Tor**;
  the hostname is never resolved locally.
- `hostname` — used only for TLS SNI and the HTTP `Host` header.
- `path` — the DoH endpoint path, usually `/dns-query`.

A custom entry whose `ip` does not parse as an IP literal is logged and skipped, not fatal.

### Binding and unavailable addresses

Both `listen` and `dns_server.listen` skip bind failures of kind `AddrInUse`,
`PermissionDenied` or `AddrNotAvailable`, logging each skipped address at WARN
with its reason. Serving continues when at least one proxy listener or, for DNS,
one complete UDP+TCP pair binds. If all addresses fail, binding returns an error;
any other bind error remains a hard failure rather than being skipped.

Each DNS address binds an **atomic UDP+TCP pair**: if either socket fails, the
other is released and the address is not served. There is never a half-bound
DNS listener. Only successfully bound endpoints enter local policy and override
recursion guards, including their actual ports for port-zero binds.

Occupied ports are **never taken over**. There is currently **no automatic
retry** of skipped addresses (LST-05 is not implemented), including in-use or
permission-denied addresses. A skipped address does not become a listener just
because the port is later freed or permissions change.

## Query popularity and background refresh

When the DNS listener is enabled, it opens a separate payload-free statistics
store before receiving queries. Each supported, parsed request with a question
counts its **first** question once, before local policy, cache, backend admission
or overload handling. Case and the DNS root spelling are normalized; name/type/
class remain distinct observations. Malformed packets, response packets, missing
questions, unsupported opcodes and AXFR/IXFR do not count. Prefetch does not count.

Popularity sums all observed types/classes for a domain over the precise rolling
30-day window `(highwater - 2,592,000 seconds, highwater]`; a domain qualifies only
when its total is **greater than 100**. The persisted clock high-water mark never
moves backwards. Trusted live receipt timestamps can advance that high-water
mark even if the worker's current UTC has rolled back before processing them;
these receipts are not untrusted restored rows. During live clock rollback,
observations retain their original UTC seconds and count only when those seconds
remain inside the trusted high-water window; they are never restamped to its end.
On reopen, a persisted
high-water mark ahead of current UTC causes restore to fail without pruning
history. Genuine rollback and plausible future tampering cannot be distinguished;
correct the clock before reopening rather than resetting the high-water mark.
Each qualifying domain's observed type/class tuples are refreshed,
not an invented A/AAAA-only set. Startup evaluates stored observations before
prefetch; evaluation repeats every two hours independently of a running cycle.
One sequential cycle is active at a time, paging immutable generations in groups
of at most 128 tuples rather than collecting the entire history in memory.

Refresh repeats current local preflight, then bypasses even a fresh cache entry
and uses the ordinary miss route: first matching override or the current Tor
provider pool, with actual listener endpoints in recursion guards. It copies no
provider configuration, override table or packet history into statistics. One
background exchange uses the same 64 backend slots, only admitting when more than
one slot is available; foreground local/cache replies remain admission-free and
UDP misses never queue. A single 30-second deadline covers local preflight,
background admission, tunnel acquisition and exchanges. Failed/unavailable Tor,
invalid packets and deadlines do not evict valid cache entries or extend TTLs.
Successful positive/alias/negative answers retain ordinary packet-cache semantics.

Statistics contain **sensitive browsing metadata** (normalized names, types,
classes, timestamps and counts), though no client address, full query/answer
packet or answer data is stored. Protect the operator-owned cache directory;
this is not encryption or protection against another user who can modify that
directory. Ingress is bounded (4096 messages), nonblocking and drop-newest
(queue-full), with 256-event SQL batches on one dedicated thread. Slow healthy
maintenance/publication can also fill the queue; pressure drops do not necessarily
mean a disk fault. Acceptance means queued, **not
already durable**. Accounting failures are logged; foreground service continues
in an explicitly degraded mode. Inspect loss/unsaved counters rather than treating
popular output as lossless traffic measurement. Explicit shutdown stops socket
producers and cancels background networking, drains accepted statistics and
publishes final popularity, then drains cache publication and performs the final
answer-cache save.

### Local inspection schema (version 2)

Version 1 stores are migrated by adding `expired=0`; historical insertion versus
expiry cannot be reconstructed after pruning, so legacy `saved` totals are
preserved rather than retrospectively reclassified.

For the normal `*.dns-cache` answer-cache path, sibling files are
`*.dns-query-statistics.sqlite3` and `*.dns-popular`. The SQLite store uses WAL
and can have `-wal`/`-shm` companions. It is separate from the answer-cache binary.

- `meta`: singleton `id=1`; `schema_version`, `highwater`, `generation`,
  `refreshed_at`, `accepted`, `saved`, `expired`, `dropped_full`, `unsaved`,
  `invalid_restored`, `last_error`.
- `query_seconds`: `domain`, numeric `rr_type`, numeric `class`, UTC Unix
  `second`, integer `count`; primary key `(domain,rr_type,class,second)`.
- `domain_summary`: primary-key `domain`, summed `count`, UTC Unix `refreshed_at` and
  `last_seen` (maximum accepted observation second).
- `popular_targets`: `generation`, `domain`, `rr_type`, `class`, `count`;
  primary key `(generation,domain,rr_type,class)`. Tuple counts are not domain totals.

The atomically replaced UTF-8 `.dns-popular` file is tab-separated, ordered by
normalized absolute domain (including trailing dot); its exact header is
`domain\tcount\trefreshed_at`. Each row contains a qualifying domain's total and
an RFC 3339 UTC refresh timestamp. It is a publication, not an input work queue:
editing it does not seed prefetch. SQLite is the authoritative ledger. Do not
modify a live ledger. Stable accounting is
`accepted = saved + expired + unsaved + pending`. Pending counts are
`accepted - saved - expired - unsaved` (clamped at zero for concurrent inspection).
`saved` is cumulative inserted observations at their original receipt seconds,
including rows subsequently pruned; it is **not** the current-window population.
`expired` counts valid accepted receipts already outside the logical window when
processed, not later pruning of previously inserted rows. `unsaved` represents
accepted events discarded after persistence/validation failure, while
`dropped_full` represents rejected ingress. Queue-pressure drop-newest behavior
is unchanged by expiry classification.

History has no arbitrary top-N/popular-domain cap: disk usage grows with accepted
`domain/type/class/second` cardinality within the rolling window. Expired-row
`DELETE` permits SQLite free-page reuse; it does not physically compact the file.
A persistent SQL fault latches accounting degradation for that worker lifetime;
restart the listener after correcting the storage fault. Publication-only errors
can be retried by later evaluation. No silent top-N truncation is applied.

With the listener stopped (or for read-only inspection of a live WAL database),
use SQLite's CLI and quote the operator path; replace this example with your
actual cache sibling path:

```sh
sqlite3 -readonly "tor-socks5.dns-query-statistics.sqlite3" "SELECT schema_version, highwater, refreshed_at, accepted, saved, expired, dropped_full, unsaved, last_error FROM meta WHERE id=1;"
sqlite3 -readonly "tor-socks5.dns-query-statistics.sqlite3" "SELECT domain, count, last_seen, refreshed_at FROM domain_summary WHERE count>100 ORDER BY domain;"
sqlite3 -readonly "tor-socks5.dns-query-statistics.sqlite3" "SELECT domain, rr_type, class, SUM(count) AS observations FROM query_seconds GROUP BY domain, rr_type, class ORDER BY domain, rr_type, class;"
```

## Pointing a client at it

The default port is deliberately non-standard, so use a stub resolver or forwarder that
supports custom ports — e.g. systemd-resolved (`DNS=127.0.0.1:15353`), or ad-hoc:
`dig @127.0.0.1 -p 15353 example.org`.

## Providers

The pool ships with 36 built-in public DoH providers (Cloudflare, Google, Quad9, AdGuard,
Mullvad, ControlD, NextDNS, …). They are tried in a fixed order, falling through to the
next entry on error or timeout — no scoring or racing. Custom entries are appended after
the built-ins, so they win only if every earlier entry fails; duplicates by `(ip, hostname)`
are dropped, keeping the first. The full list lives in
`packages/dns-server/src/providers.rs`. Honest caveat: a few of the base-20 entries
inherited from the bridge-probe list have since become HTTP/2-only frontends — such entries
simply never win and cost one timed-out attempt each (details in the providers.rs module docs).

## Exceptions (per-mask overrides)

`dns_server.overrides` is an operator-listed array of hostname masks that skip the
DoH-over-Tor pool entirely: each entry pairs a list of glob masks (`patterns`) with the resolver
that handles matching hosts — the operating-system resolver (`resolver: system`, 10s
timeout) or one plain DNS server (`resolver: dns` + `server: ip:port`, UDP with a
TCP retry on truncation, 5s timeout). Masks are scanned in list order and the FIRST
match wins; a host matching no mask keeps the default pool path. Override answers
share the same TTL cache as ordinary answers.

> **Warning:** a host matching a mask deliberately LEAVES the Tor tunnel. The plain
> DNS or OS-resolver exchange runs over the machine's own network, so the queried
> name is visible to the local network and ISP — a conscious, operator-opted
> exception to this document's security model. Do not add masks for hosts whose
> names you do not want to reveal to the local network/ISP.

```ktav
dns_server.overrides: [
    {
        ## all three fields are required; `server` stays empty for `system`
        patterns: [
            *.lan
            *.home.arpa
        ]
        resolver: system
        server:
    }
    {
        patterns: [
            ns.home.arpa
        ]
        resolver: dns
        server: 192.168.1.1:53
    }
]
```

One entry takes any number of masks; each mask becomes its own exception in list
order, all sharing the entry's resolver. A lone string (`patterns: *.lan`) is read
as a one-element list. The older single-mask key `pattern` is no longer accepted:
a config that still uses it is rejected at start, and `tor-socks5 config migrate`
rewrites every `pattern: X` as `patterns: [X]`.

**Mask syntax:** `*` matches any run of characters including none; matching is
case-insensitive and always against the WHOLE host, never per-label. A mask with
no `*` is an exact hostname match. The deliberate edge case: `*.example.com` does
NOT match the bare `example.com` (the mask's literal `.` must appear in the
host) — list both entries if you want both covered. The exact edge-case semantics
live in the `matches()` doc comment in `packages/dns-server/src/overrides.rs`.

**Forgiving conversion:** as with the rest of the configuration, a broken entry is
logged and skipped, not fatal: a `dns` entry whose `server` does not parse is
skipped; a `system` entry with a non-empty `server` warns and keeps the system
resolver; an empty mask is skipped (the entry's other masks stay), and so is an
entry left with no usable mask.

## Caching

Answers are cached on disk in a sibling file of the main config: same directory, same file
stem, fixed `.dns-cache` suffix (`/etc/tor-socks5.ktav` → `/etc/tor-socks5.dns-cache`;
`./tor-socks5.dns-cache` when the config has no path on disk). The cache is TTL-aware —
a fresh hit is answered inline in the receive loop, with no Tor round-trip. It is flushed
every 5 minutes and saved once more, best-effort, at shutdown. Periodic publication
is polled concurrently with listeners, with at most one save outstanding; shutdown
closes socket work and joins cancelled prefetch, drains accepted statistics and
final popularity publication, drains any active cache publication, then performs
the serialized final save. The synchronized owned-lifecycle regression drives
101 real UDP/TCP queries, observes network drop and TCP EOF/listener closure,
and holds the statistics-drain gate while asserting the final cache-save callback
has not started. It then releases the gate and observes durable counts/popularity
and the real cache save through the production save helper. The separate
precancelled-startup regression checks restored popularity and cache output only,
not their relative publication order.
Positive answers and
SOA-backed NXDOMAIN/NODATA results are cached with their remaining lifetimes;
failures are not negative DNS answers. Legacy address-only cache data is not a
source of synthesized mixed-family answers.

## Local policy, deadlines and admission

Before cache or any external resolver, `localhost` and its subdomains return
`127.0.0.1` for A, `::1` for AAAA, and NOERROR/NODATA for other types. IPv4
127/8 reverse names and the IPv6 `::1` reverse name return PTR `localhost.`.
These queries never acquire a backend slot, consult Tor, or follow an override.
PTR queries for an explicitly bound non-loopback listener IP, or an actual local
IP covered by a same-family wildcard bind, return NOERROR/NODATA unless a matching
explicit override is configured. Wildcard detection uses a route-only UDP
connect/local-address probe (no payload), bounded to 100ms, before cache or backend
admission. IPv4-mapped IPv6 addresses use IPv4 coverage. Binding reads the actual
`IPV6_V6ONLY` option independently on both UDP and TCP sockets. Only an IPv6
unspecified socket with that option disabled contributes a derived
`0.0.0.0:bound-port` endpoint to local policy and recursion guards; no family or
OS-default guess is used. Getter errors fail binding rather than invent coverage,
and production does not change the socket option. Localhost, loopback and
exact-bound-IP fast paths do
not probe. A failed/expired probe retains normal routing; unrelated private and
external reverse names are not suppressed. Policy uses actual bound UDP/TCP
addresses, including ports chosen by port-zero binds.

Misses share **64 backend resolution slots** across UDP and TCP. UDP never waits
for a slot: local/cache replies remain inline while overload receives bounded,
best-effort SERVFAIL without a queued task or extra upstream work. TCP has a
separate 64-connection admission cap; excess connections are closed. Each TCP
frame has one 30-second prefix-and-body deadline, writes have a 30-second cap,
and a connection has a finite five-minute lifetime. Malformed/partial frames and
expired framing/write deadlines close the connection, never restart a partial
frame.

One **absolute 30-second deadline** covers the entire miss, including current
Tor tunnel acquisition, override resolution and all provider traversal. Attempts
do not refresh it. Missing Tor, exhausted providers and expired deadlines return
SERVFAIL; NOERROR, NXDOMAIN, REFUSED, NOTIMP and FORMERR are terminal DNS
results, not provider outages. Only SERVFAIL is a temporary DNS rcode eligible
for fallback; NODATA is NOERROR with an empty answer. Resolution/socket futures are listener-owned and
cancelled on shutdown, releasing admission resources before the final cache save.

Direct and system override resolvers receive the actual bound endpoints to reject
self-recursion, including port-zero endpoints. System resolver callers wait for
bounded capacity within their query budget, rather than failing immediately busy.
Do not configure an override whose
upstream forwards back to this listener: multi-hop forwarding loops are not a
supported routing scheme.

## Limitations

- **No EDNS0.** An OPT pseudo-RR is ignored, not echoed. UDP answers are capped at the
  legacy 512-byte payload with the TC=1 fallback (RFC 1035 §4.2.1); stub resolvers fall
  back to TCP on truncation, which the server fully supports.
- **Typed DNS answers.** Resolution and cache keys include normalized name, type and
  class. Responses retain the backend rcode and full answer/authority/additional
  sections (including CNAME, SOA, MX, TXT, HTTPS/SVCB and unknown records); A and
  AAAA queries are not merged. The client ID and first question are echoed, RD/CD
  follow the client, and AD is cleared: this frontend does not validate DNSSEC.
- **First question only.** Only the first QUESTION-section entry of a message is answered.
- The DNS listener is an auxiliary service: a runtime error exit is logged, not fatal —
  the SOCKS5 proxy path keeps running.

## Security note

Queries for hosts matching no `dns_server.overrides` mask leave the machine only
inside the Tor tunnel; the per-mask overrides (Exceptions section above) are the one
deliberate, operator-opted exception. The DoH provider still sees the queried names
(it terminates TLS), but only at a Tor exit's IP address — not yours.
`custom_doh_providers` (with `disable_builtin_providers`) shifts that trust to whichever
operators you configure.
