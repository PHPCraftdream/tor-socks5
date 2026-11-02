# tor-socks5-client-acl

Client access control for local SOCKS5 and DNS listeners:
a validated allow-list of client IP addresses — a small layer free of
dependency cycles, shared by the configuration schema, authentication path, DNS server,
CLI and Android FFI.

The entire list is a single scalar string (`AllowedClients`), parsed
eagerly when the configuration is loaded: an invalid value is rejected before
the listener starts, not when a connection arrives.

## Grammar

Tokens are comma-separated, with surrounding whitespace trimmed from each. Every token is validated,
including tokens after `*`:

- `*` — allow all clients.
- `loopback` (strictly lowercase) — only `127.0.0.0/8` and `::1`.
- An exact IPv4/IPv6 literal (`192.168.1.5`, `2001:db8::1`).
- IPv4 wildcards: decimal octets or a whole `*` per component
  (`192.168.*.*`, shorthand `192.168.*` == `192.168.*.*`; shorthand uses
  fewer than 4 components with a trailing `*`). Leading zeros are forbidden (`01` is
  an error).
- IPv6 wildcards: hex groups or a whole `*` per hextet (`2001:db8:*` =
  prefix `2001:db8` with any suffix; `2001:db8::*` = prefix `2001:db8`, five zero hextets
  and any final hextet). At most one `::` compression is allowed; compressed hextets
  are always exact zeros, never wildcards.
- Mapped wildcards: a dotted IPv4 suffix is allowed ONLY within the exact
  prefix `::ffff:` (`::ffff:192.168.*.*`); wildcards are preserved
  octet by octet. The fully expanded hextet form is also supported:
  `0:0:0:0:0:ffff:192.168.*.*` (including `0:0:0:0:0:ffff:c0a8:*`).
  Both compile to an equivalent IPv4 rule. Any other IPv6 mask
  remains an IPv6-only rule and does not match IPv4 peers.

Hostnames, CIDR, ports, zone IDs and ranges are parse errors.
A peer with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is normalized to
ordinary IPv4 before matching; IPv4-compatible IPv6 addresses are not.

## Usage

```rust
use client_acl::AllowedClients;

let acl: AllowedClients = "127.*, ::1".parse().expect("valid allow-list");
assert!(acl.allows("127.0.0.1".parse().unwrap()));
assert!(!acl.allows("10.0.0.1".parse().unwrap()));
assert_eq!(acl.as_str(), "127.*, ::1");
```

`Default` is `*` (allow everyone): older configurations without the new keys retain
their previous behavior.
