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
tor-socks5 onion new <NICK> --bridge-group NAME [--bridges N]  # into a bridge group
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
- **`--bridge-group NAME [--bridges N]`** (on `new` and on `import`) writes the
  group into the service's entry, so a service can be created in a bridge
  group without editing the file: the name is `a-z 0-9 _ -`, at most 25 bytes,
  and `bridges` is 1 to 8 (default 2). `--bridges` needs `--bridge-group`, and
  a wrong value is refused before any key is made or the file is touched.
  Without the flags the entry gets no group fields; `--force` replaces only
  the identity, so an existing group (and its `bridges`) stays unless the
  flags state a new one, and an unstated `--bridges` keeps the count the
  entry already has.
- **`remove`** requires `--yes`; there is no undo.
- **The file holds secret keys.** Keep it private, back it up with the same
  care as a private key. On Unix it is written with mode `0600`; it is in
  `.gitignore`. Whoever has the `key` can publish the address.
- **The Arti keystore is a copy.** At each start the key of the file is put
  into the keystore at
  `<config dir>/arti-data/state/keystore/hss/<nick>/ks_hs_id.ed25519_expanded_private`
  (the file arti reads; a service in a bridge group uses the keystore under
  `arti-data/group-<name>/state/` instead). A key that an older version left in the keystore
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

### Reading the startup log

Every line below carries the service `nickname`; times are in seconds.

- `onion service got a launch slot` — `waited_s` in the queue for one of the
  4 launch slots and `slots_in_use`.
- `onion service address available: onion service starting` —
  `address_after_s` since the launch.
- `onion service bootstrapping`, `reachable`, `reachable but degraded`,
  `unreachable, attempting recovery` — `since_launch_s`, the `previous` state
  and, for the degraded ones, `problem`: how many descriptor uploads failed
  and how (timed out, fatal).
- `onion service launch slot released` — `reason` (`status`: the service
  reported one; `cap`: it held the slot for the whole 90 s without a status;
  `shutdown`) and `held_s`.
- `onion service: failed to complete rendezvous handshake` — `error` with the
  whole chain of causes and `handshake_s`; successful handshakes log
  `handshake_s` at `debug`.
- `onion services starting` (at most every 15 s while some service has no
  status yet) and `onion services: every service has reported a status` — the
  number of services per state, and for the final line the median and the
  slowest time to the first status.

A service reports its first status only after its descriptor uploads have
finished or given up. Arti retries each HsDir upload for up to **5 minutes**
(a constant inside Arti), so when even one of the service's HsDirs does not
answer, the first status comes at least 300 s after the launch. The detail
per HsDir is Arti's own log: run with `RUST_LOG=info,tor_hsservice=debug`.

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

## Many services

Every onion service costs circuits. In steady state Arti (0.48, the vendored
stack) keeps **3 introduction-point circuits** per service — the minimum; it
allows 3..=20, and up to 5 relays are used only while some introduction points
are faulty. Each service uploads its descriptor to **8 HsDirs** per time
period (2 replicas × 4), and re-uploads are rate-limited to one per minute
per service.

Circuits are a shared resource. By default **all circuits of the process** —
introduction, HsDir uploads, rendezvous and ordinary traffic alike — go
through **one bridge**: Arti uses the first usable of its 3 primary guards,
and when that bridge fails, every circuit is rebuilt at once on the next one.
Arti also fills its onion circuit pool one circuit at a time, so many
services starting together exhaust the pool and then build their circuits on
demand in a burst.

The server paces this:

- **Identities are settled up front.** The identities of all enabled services
  are settled before anything launches, and the onion services file is
  rewritten once (not once per keyless service). A service whose identity is
  unusable does not start and does not stop the others; if that single write
  fails, the services that would have needed a new key recorded do not
  start.
- **Gradual start.** At most 4 services are in their launch phase at once. A
  service holds its slot until it reports running, reachable-but-degraded or
  broken — for at most 90 s, or until shutdown. Relaunch attempts go through
  the same gate, and the retry backoff (30 s doubling to 5 minutes) is
  spread by ±20 %. Services start in the order of the services file (best
  effort).
- **Stream limits:** 256 concurrent forwarded streams per service and 512
  across all services together.
- **More than 10 enabled services log a warning at start** — the setup is
  beyond what is known to work, and the warning names this documentation.
  It is not an error, and nothing is refused.

How far you can go is not settled. Hosting onion services is marked
experimental by the Arti authors. External reports (the OnionPress issues #75
and #96 on GitHub, against Arti 2.x) saw reliable operation at about
10 services per process and rendezvous failures from about 13–20. Treat
that as an external data point, not as a guarantee. Our own measurement
follows.

### What we measured

One setup, one run per row — a Windows release build with 19 reachable
webtunnel bridges, `tor.circuit_hops: 3`, and every service forwarding to the
same local HTTP server. After all services had reported a status and a
further 5 minutes of settling, each address was requested through the proxy
itself (`curl --socks5-hostname`, 4 at a time, 60 s limit); a miss was
retried once after a minute. "Up" is the time from the start line to the
first running or reachable-but-degraded status.

| Services | `guard_spread` | Answered at first try | Answered after one retry | Median up | Slowest up | Descriptor-upload timeouts logged |
|---------:|:--------------:|----------------------:|-------------------------:|----------:|-----------:|----------------------------------:|
| 5  | 1 | 4  | 4  | 153 s | 531 s  | 22  |
| 10 | 1 | 8  | 9  | 361 s | 656 s  | 54  |
| 20 | 1 | 15 | 18 | 462 s | 840 s  | 185 |
| 20 | 3 | 16 | 17 | 424 s | 783 s  | 166 |
| 40 | 1 | 32 | 39 | 773 s | 1115 s | 314 |
| 40 | 3 | 30 | 37 | 631 s | 1377 s | 506 |

What the runs show:

- **No collapse up to 40.** No service reached the broken status, no launch
  failed, no `ERROR` line was logged, the bridges stayed reachable (at worst
  one of the 19 missed a probe), and the working set stayed under 110 MB.
- **The cost is time and first requests.** The start takes longer as the count
  grows (the gate launches at most 4 at a time; the last of 40 took about
  19 minutes to come up at `guard_spread: 1`), and the share of services that answer the very first request falls
  to about 80 %. Most services settle at "reachable but degraded" rather than
  "reachable" — the dominant warning is a descriptor upload to an HsDir that
  timed out — and they still answer. A client should retry a first request.
- **A few addresses stay silent.** Only three of the 40 addresses did not
  answer even after the retry (one of them in every run it took part in);
  every other miss answered on the retry. The failures follow the address
  more than the count. We did not investigate why.
- **`guard_spread: 3` gave no gain here.** With every bridge healthy the
  results are within the noise of a single run, and the warnings roughly
  doubled at 40 services. What it is for — keeping part of the circuits
  alive while one bridge fails — was not tested.

This is one network, one machine and one run per row, so it does not
contradict the external reports: it shows that 40 services can work, not
that they will. The warning therefore stays at 10 enabled services.

In practice: start with few services, watch the status lines, and raise the
count gradually. Set `tor.guard_spread: 2` or `3` only for failure isolation
— provided you have at least that many working bridges (see
[bridges](../bridges.md)) and accept that more bridges see your traffic. For
much more than ~10 services, split them across separate tor-socks5 processes,
each with its own config directory and its own bridge set.
[Bridge groups](#bridge-groups) do the same inside one process, but are not
verified live yet.

## Bridge groups

By default every service uses the process-wide Tor client and so every bridge
of the process: one failing bridge disturbs all services, and one bridge
carries all their circuits. A **bridge group** gives some services a Tor client
of their own, limited to a few bridges:

```ktav
services: [
    {
        nickname: web-a
        bridge_group: edge-a
        bridges: 2
        ports: [ 80=127.0.0.1:8080 ]
    }
    {
        nickname: web-b
        bridge_group: edge-b
        bridges: 2
        ports: [ 80=127.0.0.1:8080 ]
    }
]
```

- `bridge_group` — the group's name: `a-z 0-9 _ -`, at most 25 bytes. Services
  with the same name share one client. Without it the service stays on the
  process-wide client, as before.
- `bridges` — how many bridges the group uses, `1` to `8`, default `2`. It
  needs `bridge_group`, and the enabled services of a group must state the
  same number. Keep `2` or more: a group with one bridge depends on that
  bridge alone and is down from its failure until a replacement is claimed.
- **From the CLI.** `onion new web --bridge-group edge-a --bridges 2` (the same
  flags work on `onion import`) writes the fields into the entry; nothing has
  to be typed into the file by hand. `onion show` prints the group of a
  service, and `--force` keeps the group unless the flags name another one.
  All enabled services of a group must still state the same `bridges`.
- **Same backend, several addresses.** The two services above forward to the
  same local port, each through its own bridges: one bridge failing takes down
  one address, not both. Tor has no way to put two addresses under one name, so
  the clients must know both addresses and try the second when the first does
  not answer. One group with `bridges: 2` or more is the transparent
  alternative: one address that survives the loss of a bridge.
- **Which bridges.** Every group gets its own bridges from the working list of
  the process, in group-name order over the list sorted by bridge line, so the
  same list gives the same assignment at every start. When the list is smaller
  than the groups need (groups x `bridges` above the number of working
  bridges), the groups share bridges and a warning names them. A group never
  starts without bridges: a client without bridges would reach Tor directly.
- **Failover inside a group.** Up to 3 of the group's bridges carry circuits at
  once; the rest stand by. A group's circuits therefore do not all depend on
  one bridge, whatever `tor.guard_spread` says (that setting is for the
  process-wide client only).
- **Cost.** Every group is a Tor client of its own: one more pluggable-transport
  process, one more set of connections to its bridges, a bootstrap at start.
  The group reads the directory cache of the process client, so it does not
  download the consensus again, but the first start waits for the process
  client to bootstrap. With many groups the bridges see more connections from
  one address, and each bridge sees only the services of its group.
- **Where the state lives.** `<config dir>/arti-data/group-<name>/` holds the
  group's guard state and its keystore (the services file stays the source of
  keys). The log lines of a group carry `group=<name>` next to the nickname.
- **Maintenance.** A group's client is supervised. Its bridges are claimed
  from the working list of the process before every bootstrap attempt and on
  every `[watchdog]` tick: a bridge the process dropped is replaced by a free
  one, never by one another group holds, and a bridge is kept until the client
  accepted its replacement. A failed or stuck bootstrap is retried with a
  growing pause; a client with no reachable service for the watchdog's stale
  window is re-created; a group stops only when every service failed for a
  reason a new client cannot fix (keys, configuration). `[watchdog]
  enabled: false` turns this maintenance off for groups as well. A bridge counts
  as dead when the process dropped it from its working list, not by a verdict
  of its own, and a service's status is the last one published, so a client that
  hangs while still reported as running is not noticed.
- **Not verified live yet.** The configuration, the assignment, the claims
  and the supervision are covered by tests; starting a group's client against
  real bridges, replacing a bridge and re-creating a client have not been
  measured. Try one group before relying on many.

## Limitations

- **Android:** the `onion-service` cargo feature is off by default there;
  a warning is logged and configured services do not start.
- **IPv6 targets** in the `ports` list need the Ktav block-list form with
  the `::` literal marker (an unquoted `[` starts an inline compound) —
  see the "Onion services" section of the README for the exact wording.
- **`tor.circuit_hops` (2 or 3) affects only client-side onion
  circuits**; service-side length is the per-service `circuit_hops`
  (see Circuit length above and [bridges](../bridges.md)).
- **At most 256 concurrent streams per service, and 512 across all
  services together**; each connect to the local target has a **10 s
  timeout**, and a refused or timed-out target closes that stream only. A
  service whose launch fails is retried with a backoff from 30 s up to
  5 minutes.
