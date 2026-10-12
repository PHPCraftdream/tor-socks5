# tor-socks5-dns

Optional local DNS server speaking the plain DNS wire format over UDP/TCP (no HTTP/DoH frontend): client queries are answered by resolving them through public DNS-over-HTTPS providers, and every DoH request itself is tunnelled through the already-established Tor connection rather than the direct network.

Answers are cached by normalized DNS question (name/type/class), preserving full
packets and rcodes, including SOA-backed NXDOMAIN/NODATA. A and AAAA are separate
queries, not merged address lists. Localhost/subdomains and loopback PTR are
answered locally before any override or tunnel lookup. Own non-loopback bound-IP
PTR (including actual local IPs covered by a same-family wildcard) returns NODATA
unless explicitly overridden; unrelated private names keep normal routing.
Wildcard preflight uses a payload-free route probe bounded to 100ms before cache
or admission; exact-IP/localhost/loopback paths do not probe. IPv4-mapped addresses
use IPv4 coverage. Each bound IPv6 UDP/TCP socket's actual `IPV6_V6ONLY` option
is read: only dual-stack unspecified sockets add derived IPv4 wildcard coverage
at the bound port. Getter errors fail binding; socket options are not forced.

Local/cache replies bypass admission. Misses share 64 backend slots across UDP
and TCP; UDP overload receives bounded SERVFAIL without waiting or queued work.
One absolute 30-second miss deadline includes tunnel acquisition and every
provider/override attempt. System resolver callers wait for bounded capacity
within the query budget, not immediate busy rejection. TCP connections have a
separate 64-connection cap and finite
framing, output and lifetime limits. Scoped listener work is cancelled at shutdown;
actual bound endpoints (including ephemeral ports) are passed to recursion guards.
AD is cleared because this frontend does not validate DNSSEC. UDP retains the
legacy 512-byte TC/TCP fallback; EDNS is not implemented.

Positive and negative cache lifetimes survive restarts without rejuvenation.
Periodic saves run concurrently with listeners, at most one outstanding, and
explicit shutdown stops owned networking and joins cancelled prefetch, drains
accepted statistics/final popularity, then drains active cache publication before
the serialized final save. Only
SERVFAIL is a temporary DNS failure; other valid terminal rcodes are forwarded.

The listener also persists payload-free query popularity and refreshes observed
popular question tuples at startup and every two hours. Background resolution
uses the same local policy, overrides, Tor provider pool and recursion guards,
bypasses fresh cache hits, and retains valid cache entries on failure. One
sequential background exchange shares the 64 backend slots while reserving
foreground headroom; prefetch itself never counts as client traffic. Statistics
are sensitive local browsing metadata; protect the cache directory. Store schema,
loss accounting and inspection format are documented in `docs/dns-server.md`.

The crate publishes as `tor-socks5-dns`, while the library target keeps the in-tree name `dns_server` — in code it is `use dns_server::…`.

The crate is fully implemented: an on-disk TTL-aware cache, a DoH-over-Tor client with a fixed-order provider pool (36 built-ins plus operator entries), and the UDP/TCP listener. Operator docs: `docs/dns-server.md` (or `tor-socks5 help dns-server`).
