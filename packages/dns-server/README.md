# tor-socks5-dns

Optional local DNS server speaking the plain DNS wire format over UDP/TCP (no HTTP/DoH frontend): client queries are answered by resolving them through public DNS-over-HTTPS providers, and every DoH request itself is tunnelled through the already-established Tor connection rather than the direct network.

Answers are cached on disk with TTL awareness, so restarts keep serving still-fresh answers without paying a new Tor round-trip.

The crate publishes as `tor-socks5-dns`, while the library target keeps the in-tree name `dns_server` — in code it is `use dns_server::…`.

The crate is fully implemented: an on-disk TTL-aware cache, a DoH-over-Tor client with a fixed-order provider pool (36 built-ins plus operator entries), and the UDP/TCP listener. Operator docs: `docs/dns-server.md` (or `tor-socks5 help dns-server`).
