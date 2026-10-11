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

- `listen` also accepts a single scalar string (`dns_server.listen: 127.0.0.1:15353`),
  the same rule as the SOCKS5 `listen` option.
- `ip` — the IPv4/IPv6 literal the DoH TCP connection is opened to **through Tor**;
  the hostname is never resolved locally.
- `hostname` — used only for TLS SNI and the HTTP `Host` header.
- `path` — the DoH endpoint path, usually `/dns-query`.

A custom entry whose `ip` does not parse as an IP literal is logged and skipped, not fatal.

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
DoH-over-Tor pool entirely: each entry pairs a glob `pattern` with the resolver that
handles matching hosts — the operating-system resolver (`resolver: system`, 10s
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
        pattern: *.lan
        resolver: system
        server: 
    }
    {
        pattern: ns.home.arpa
        resolver: dns
        server: 192.168.1.1:53
    }
]
```

**Mask syntax:** `*` matches any run of characters including none; matching is
case-insensitive and always against the WHOLE host, never per-label. A pattern with
no `*` is an exact hostname match. The deliberate edge case: `*.example.com` does
NOT match the bare `example.com` (the pattern's literal `.` must appear in the
host) — list both entries if you want both covered. The exact edge-case semantics
live in the `matches()` doc comment in `packages/dns-server/src/overrides.rs`.

**Forgiving conversion:** as with the rest of the configuration, a broken entry is
logged and skipped, not fatal: a `dns` entry whose `server` does not parse is
skipped; a `system` entry with a non-empty `server` warns and keeps the system
resolver; an entry with an empty `pattern` is skipped.

## Caching

Answers are cached on disk in a sibling file of the main config: same directory, same file
stem, fixed `.dns-cache` suffix (`/etc/tor-socks5.ktav` → `/etc/tor-socks5.dns-cache`;
`./tor-socks5.dns-cache` when the config has no path on disk). The cache is TTL-aware —
a fresh hit is answered inline in the receive loop, with no Tor round-trip. It is flushed
every 5 minutes and saved once more, best-effort, at shutdown. Periodic publication
is polled concurrently with listeners, with at most one save outstanding; shutdown
closes socket work, drains that publication, then performs the serialized final save.
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
