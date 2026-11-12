# Onion services

`tor-socks5` can publish local services through Tor as **onion services**
(v3). The machine keeps no listening port on the public internet: no port
forwarding, no NAT traversal, no public IP required. Remote clients reach
the service over the Tor network through a `<56 chars>.onion` address, and
the connection is end-to-end encrypted between the client and this machine.

## Why

- No router changes: the local service stays bound to `127.0.0.1`; Tor
  dials out to the rendezvous relays, nothing listens inbound.
- The `.onion` address is derived from the service's Ed25519 key, so the
  address itself authenticates the service — clients get pinning for free.
- Reachable from anywhere Tor works, including behind carrier-grade NAT.

## Quick start

The services are kept in their own file next to the main config,
`tor-socks5.onion.ktav` (the same sibling convention as
`tor-socks5.bridges.ktav`). It is the only source of the services: per
nickname it holds the ports, the address and the secret key.

1. Create the service. This generates the key, works out the address and
   records both, with the ports, in the file:

   ```bash
   tor-socks5 onion new web --port 80=127.0.0.1:8080
   ```

   `--port ONION_PORT=HOST:PORT` can be repeated. Without any `--port` the
   service is created disabled and its ports are added to the file by hand.
   Or write the entry yourself and skip this step: a service without a key
   gets one at its first start, and the program writes the key and the
   address back into the file.

2. The file now looks like this:

   ```ktav
   services: [
       {
           nickname: web
           enabled: true
           address: <56 chars>.onion
           key: <base64 of the key file>
           ports: [ 80=127.0.0.1:8080 ]
       }
   ]
   ```

   Each `ports` entry maps an onion port to a local target as
   `onion_port=host:port`. Here onion port 80 forwards to a local web
   server on `127.0.0.1:8080`.

3. Start the server. Once Tor is ready the service starts and its address
   is logged — look for a line naming the nickname next to a
   `<...>.onion` address. The same address is always in the file and in
   `tor-socks5 onion list`.

4. Verify from another machine (through this proxy's SOCKS5 listener,
   default `127.0.0.1:1080`):

   ```bash
   curl --socks5-hostname 127.0.0.1:1080 http://<address>.onion
   ```

   `--socks5-hostname` matters: the hostname is resolved on the Tor side,
   never in the local resolver.

## The services file and the keys

All operations are `tor-socks5 onion ...` subcommands working on the file:

```bash
tor-socks5 onion new <NICK> [--port ...]...    # generate a key + address, record the service
tor-socks5 onion new <NICK> --vanity prefix    # mine an address with a prefix
tor-socks5 onion list                          # nicknames, addresses, ports
tor-socks5 onion show <NICK>                   # one service in detail
tor-socks5 onion export <NICK> --out <FILE>    # write a keystore-format file
tor-socks5 onion import <NICK> <FILE>          # restore / move a key
tor-socks5 onion remove <NICK> --yes           # delete the service and its key
```

- **The file is the source.** The nickname in the config of a service is
  the same name under which `list`, `show`, `export` and `remove` find it;
  its `key` and `address` sit right in its entry.
- **`address` is stated, not chosen.** It is derived from the key. If the
  file states an address that the key does not give, the service does not
  start (the log names both addresses, never the key).
- **A service without a key** gets one at its first start, and the program
  rewrites the file with the key and the address (comments are not kept).
- **`new` and `import` refuse to overwrite** an existing identity unless
  `--force` is given — overwriting changes the address. With `--port` they
  set the ports (and enable the service); without it a new service is
  created disabled and an existing one keeps its ports.
- **`remove`** requires `--yes`; there is no undo.
- **The file holds secret keys.** Keep it private, back it up with the same
  care as a private key. On Unix it is written with mode `0600`; it is in
  `.gitignore`. Whoever has the `key` can publish the address.
- **The Arti keystore is a copy.** At each start the key of the file is put
  into the keystore at
  `<config dir>/arti-data/state/keystore/hss/<nick>/ks_hs_id.ed25519_expanded_private`
  (the file arti reads). A key that an older version left in the keystore
  without a file entry is adopted at the first start and moves into the
  file, so the address stays.
- **Lock:** while the server runs and any onion service is active, it holds
  the keystore lock and writes the services file. `onion new`, `import` and
  `remove` then refuse with a "stop tor-socks5 first" message; `onion list`,
  `show` and `export` keep working.
- `export` writes a keystore-format file with mode `0600` on unix. Use
  `export`/`import` for backups and for moving a service (and its
  address) to another machine.
- **Upgrading:** an `onion_services` section in the main config is the old
  layout. Loading it fails with the command that converts it,
  `tor-socks5 config migrate`, which moves the section into the services
  file; the keys follow at the first start.

## Vanity addresses

`onion new --vanity PREFIX` repeatedly generates candidate keys until the
resulting address starts with the prefix. The prefix is base32 — only the
letters `a`–`z` and digits `2`–`7`, up to 8 characters. Each extra
character multiplies the work by 32; the expected number of attempts is
`32^len`.

On one machine the tool measured roughly **32,000 attempts per second per
thread** — your rate is printed live while it runs, so judge by that
number, not this table. Expected time = expected attempts / (rate ×
threads):

| Prefix length | Expected attempts | ~1 thread @ 32k/s | ~8 threads @ 32k/s |
|---------------|-------------------|--------------------|---------------------|
| 1 | 32 | ≈ 1 ms | ≈ 1 ms |
| 2 | 1,024 | ≈ 32 ms | ≈ 4 ms |
| 3 | 32,768 | ≈ 1.0 s | ≈ 0.13 s |
| 4 | 1,048,576 | ≈ 33 s | ≈ 4.1 s |
| 5 | 33,554,432 | ≈ 17.5 min | ≈ 2.2 min |
| 6 | 1,073,741,824 | ≈ 9.3 h | ≈ 1.2 h |
| 7 | 34,359,738,368 | ≈ 12.4 days | ≈ 1.6 days |
| 8 | 1,099,511,627,776 | ≈ 398 days | ≈ 50 days |

These are **averages**, not guarantees — a lucky 7-character prefix may
land in minutes and an unlucky 3-character one may take ten times the
estimate. Without `--timeout` the command refuses to start when the
estimate exceeds one hour; `--threads` and `--timeout` control the run.
`Ctrl-C` cancels at any point without writing any key.

In practice: 1–4 characters is casual; 5–6 characters is hours-scale on
8 threads; 7+ is days to months — think twice.

## Security

- **The address is the public key.** Anyone who learns the `.onion`
  address can attempt to connect — the address provides no access
  control by itself. Restrict the local target as needed.
- **Losing the key loses the address forever.** There is no recovery; a
  new key means a new address. Keep an `onion export` backup.
- **Leaking the key is impersonation.** Whoever holds the private key can
  publish the same `.onion` address and pose as your service. Treat
  the services file, exported files and the keystore directory as secrets.
- **Non-loopback targets are warned about.** Forwarding an onion port to
  a target off the local machine widens who can reach that target;
  the config validator logs a warning for non-loopback targets.
- **File permissions:** `onion export` writes the key file with mode
  `0600` on unix.
- **Keystore lock:** see Key management above — mutations require the
  server to be stopped (or to run no services).

## Statuses and diagnostics

Each configured service is tracked through a lifecycle, logged with its
nickname:

- **bootstrapping** — Tor is up and the service is publishing its
  descriptors;
- **reachable** — the service is published and clients can connect;
- **degraded** — the service runs, but some descriptor publications have
  failed; clients may still reach it, but treat it as partially
  published;
- **broken** — the service could not start or failed outright.

The **first start is slow** by design: the service's descriptors must be
uploaded to several HsDir relays. Observed through webtunnel bridges:

| Scenario | Introduction points | First client page load |
|---|---|---|
| Cold start (empty Tor state, new key) | — | ~5 min after "Tor is ready" (some HsDir uploads time out → `degraded`) |
| Warm Tor, new key | 3 in ~21 s | ~47 s |
| Warm restart, same key | 3 in 5–7 s | ~52 s (descriptor upload rate limit) |

The first client request takes seconds (~5–7 s observed; introduction
setup), repeat requests are fast (~0.4–0.7 s). No safe speedup was found
beyond keeping the Tor state directory between runs. If a service stays
degraded or broken: wait (uploads retry automatically), check the logs for
the failing HsDir uploads, and restart the server if it does not settle.

## Circuit length

Each entry of the services file accepts `circuit_hops` — the total number of
relays from the server to the introduction point, rendezvous point or
HsDir, the bridge included:

| `circuit_hops` | Introduction / rendezvous | HsDir uploads |
|---|---|---|
| `4` (default) | bridge → 2 relays → target | same |
| `3` | bridge → middle → target | same |
| `2` | bridge → target | bridge → middle → HsDir |

HsDir uploads never drop below three relays: HsDirs answer
`Rejecting single hop HS descriptor post` when the previous hop is a
client, and a bridge counts as one. Arti shares one onion-circuit pool per
process, so all enabled services must use the same value. Values below `4`
log a startup warning: a shorter chain trades anonymity for latency and is
meant for censorship circumvention, not anonymity. Observed with a warm
client: `2` → first request 7.4 s, repeats ~0.37 s; `3` → 4.7 s, repeats
~0.7 s.

## Limitations

- **Android:** the `onion-service` cargo feature is off by default there;
  a warning is logged and configured services do not start.
- **IPv6 targets** in the `ports` list need the Ktav block-list form with
  the `::` literal marker (an unquoted `[` starts an inline compound) —
  see the "Onion services" section of the README for the exact wording.
- **`tor.circuit_hops` (2 or 3) affects only client-side onion
  circuits**; service-side length is the per-service `circuit_hops`
  (see Circuit length above and [bridges](../bridges.md)).
- **At most 256 concurrent streams per service**; each connect to the
  local target has a **10 s timeout**, and a refused or timed-out target
  closes that stream only. A service whose launch fails is retried with a
  backoff from 30 s up to 5 minutes.
