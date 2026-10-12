# Upstream SOCKS5 egress

By default `tor-socks5` egresses through Tor. Alternatively it can forward every accepted
`CONNECT` through an **upstream SOCKS5 proxy** instead — chaining
`client → tor-socks5 → upstream → target`. When an upstream is active, **Tor is not started**
at all (no bridges required, no bootstrap).

`tor-socks5` is still the inbound SOCKS5 server (so its own user authentication, if configured,
still applies); the upstream is purely the egress hop.

## Configuration

```ktav
upstream.enabled: true
upstream.address: 127.0.0.1:9050
## optional RFC 1929 username; empty = no auth
upstream.username:
## only meaningful with a username
upstream.password:
```

## CLI flags (override the config)

```bash
tor-socks5 --upstream 127.0.0.1:9050               # enable + set address
tor-socks5 --upstream 1.2.3.4:1080 \
           --upstream-user alice --upstream-pass s3cret
tor-socks5 --no-upstream                           # force the Tor egress, ignoring the config
```

Precedence:

- `--no-upstream` wins over everything → Tor egress.
- otherwise the upstream is enabled if `--upstream` is given **or** `upstream.enabled: true`.
- the address comes from `--upstream` if present, else `upstream.address`.
- credentials come from `--upstream-user`/`--upstream-pass` if present, else the config
  (a username from either source switches auth on).

An enabled upstream with no address is a startup error.

## Protocol

The client implements RFC 1928 `CONNECT` plus optional RFC 1929 username/password. The target
host is sent as a domain name when it is not an IP literal, so DNS is resolved by the upstream
(not locally). Credentials are limited to 255 bytes each (the RFC 1929 limit).

## Security note

`upstream.password` is stored in plaintext in the config file (an accepted trade-off — the
config is local and operator-owned). It is **redacted** from any `Debug` output, so it will not
leak into logs.
