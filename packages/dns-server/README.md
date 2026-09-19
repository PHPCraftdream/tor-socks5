# dns-server

Optional local DNS server speaking the plain DNS wire format over UDP/TCP (no HTTP/DoH frontend): client queries are answered by resolving them through public DNS-over-HTTPS providers, and every DoH request itself is tunnelled through the already-established Tor connection rather than the direct network.

Answers are cached on disk with TTL awareness, so restarts keep serving still-fresh answers without paying a new Tor round-trip.

## Status

Skeleton crate: shared types ([`ResolvedAnswer`], [`DohProvider`]) and the module layout only. The on-disk cache, the DoH-over-Tor client, and the UDP/TCP listener land in follow-up work.
