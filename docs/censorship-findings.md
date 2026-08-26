# Field notes: what a transport-fingerprinting censor actually blocks

Measured on a physical device over several hours against one mobile carrier
that actively filters Tor. Recorded because the numbers change which defences
are worth building and which are busywork.

The adversary here is generic: any operator running protocol classification on
its subscribers' traffic. Nothing below depends on which one.

## The censor has two levers, not one

### Lever 1 — protocol fingerprinting (kills obfs4)

obfs4 is, by construction, a stream of bytes indistinguishable from noise: no
header, no signature, and the bridge's key is not public. Content-based
detection is therefore impossible, and no amount of reshaping the payload
changes that — there is nothing left to hide.

What the classifier reads instead is the *shape* of the flow: packet sizes,
inter-arrival timing, direction ratios, duration. Measurements from one connect
attempt over 29 freshly TCP-verified obfs4 bridges:

| stage | outcome |
| --- | --- |
| TCP reachability probe | all alive, 354–439 ms |
| obfs4 SOCKS handshake to the local PT | succeeds (24 of 24) |
| Tor link handshake started | 11 |
| Tor link handshake **completed** | **0** |

Connections survive seconds, then die. The censor is not rejecting the first
packet — it admits the flow, watches it, and kills it once it has decided. One
bridge did complete a handshake earlier in the day and even built a circuit;
90 s later the same channel was `ChanTimeout`. Arti's own verdict for the
session was `Our internet connection seems filtered`.

Two consequences worth internalising:

- **Adding more obfs4 bridges does not help.** The protocol is blocked, not the
  addresses. Going from 3 to 29 to 8088 bridges changed nothing.
- **Raising timeouts does not help.** It converts a fast failure into a slow
  one. The censor can always be slower than any budget.

`iat-mode` (obfs4's inter-arrival-time randomiser, exposed as
`bridges.iat_mode`) attacks exactly this lever and costs nothing to try, but it
is a lottery ticket, not a fix: it is client-side only, it does not remove the
"long high-entropy flow with no recognisable protocol" tell, and the censor
retrains on aggregate network-wide traffic while we tune one phone.

### Lever 2 — bandwidth starvation (kills cold bootstrap)

Once a working transport exists, the remaining lever is the bridge itself: it
is the single pipe through which a cold Arti must pull the whole Tor directory —
consensus plus the microdescriptor set, tens of megabytes. Throttle that pipe
and bootstrap never finishes, however healthy the bridge is.

Observed directly: a run that had *already* downloaded the consensus sat at
`85%: fetching relay info` and expired against a 300 s budget. Raising the
budget is again the wrong move for the same reason as above.

## What actually wins: mimicry, then don't use the pipe

### webtunnel beats the fingerprinter

webtunnel does not try to be unrecognisable; it tries to be *something else*.
The client opens an ordinary TLS connection to a real web server with a real
Let's Encrypt certificate and issues an HTTP/1.1 WebSocket upgrade. To a passive
observer, and to active probing, it is a visit to a website.

That is the structural difference from obfs4. An obfs4 bridge answers a probe
with noise — the *absence* of a protocol is itself the tell. A webtunnel bridge
answers with a website. Blocking it means blocking ordinary HTTPS to a
legitimate host, which turns the censor's decision from technical into
political.

On the same carrier, in the same session: **27 of 33** tested webtunnel hosts
were reachable, and bootstrap completed where every obfs4 bridge had failed.

### Seeding the directory cache removes the second lever

Tor's directory data is public and signed by the directory authorities, and
Arti verifies those signatures on load. It therefore does not matter where the
bytes come from — a forged cache cannot pass verification, and the data carries
no secrets. So the megabytes need not travel through the censored pipe at all.

Copying `arti-data/cache/` (`dir.sqlite3` plus the newest `con_microdesc_*`
blob) from a warm instance changed cold start from *"300 s expired at 45%"* to:

```
0%: Connecting to Tor network
21%: Fetching certificates
85%: Fetching relay info
100%: Connected          <- 6 seconds after the first line
```

This also explains an observation that had looked like a bridge-quality
difference all day: the desktop build kept working not because its bridges were
better, but because its directory cache was warm.

Caveat when seeding by hand: Arti refuses to start if anything in its cache
directory is world-writable (`must be o-w`), so fix permissions after copying.

## Implementation consequences in this repo

- `bridge-probe::usable_for_tor` must **not** reject a webtunnel line whose
  ORPort is in `2001:db8::/32`. That placeholder is normal for webtunnel — the
  real endpoint is in `url=`. Rejecting it removed the entire transport from the
  pool before anything could try it.
- DoH is a hard dependency of webtunnel, because webtunnel bridges are named by
  hostname rather than address. `hickory-resolver` must be built with the
  `webpki-roots` feature: without it the resolver's TLS root store is empty and
  every provider fails certificate verification, so DoH silently never works.
- A DoH lookup needs its own time budget, separate from the TCP probe's: it
  opens its own TLS session before it can ask anything. Sharing the probe's
  few-second budget timed out every hostname-based bridge.
- Blocked DoH providers must be bounded per provider, or they hold their
  concurrency slot for the whole budget and starve the providers that would
  have answered.
- `bridges.transport` (`any` | `obfs4` | `webtunnel`) exists because blocking is
  transport-specific and the right answer differs per network. It is a
  preference, not a filter: if the chosen transport has no live bridge, the full
  pool is still used, so a wrong choice cannot strand a user.

## The public webtunnel pool is mostly already burned

Measured against the union of three actively regenerated collectors — 240
bridge lines, 168 distinct fronting hosts:

| vantage point | host unreachable | host answers | real bridge (101) |
| --- | --- | --- | --- |
| desktop, one ISP | 148 | 20 | 3 |
| phone, a different network | 147 | 21 | — |

Two independent networks agree to within one host, so this is the state of the
pool rather than an artefact of one connection or of the probe. Of the handful
that do answer, most serve an ordinary website; three completed a WebSocket
upgrade.

The obvious reading — "there are only three webtunnel bridges in the world" —
is wrong, and the right one follows from how these lists are built. A
webtunnel bridge published on GitHub is discoverable by anyone, censors
included, so the scraped pool is a record of bridges that have *already been
handed out publicly*, which is the same as saying already burned. The bridges
that still work are the ones distributed on request through BridgeDB and moat,
rate-limited and CAPTCHA-gated precisely so they cannot be harvested.

The practical consequence is that adding more scraping collectors buys very
little: they all scrape the same exhausted set, and three of them already
agreed. What would actually raise the yield is a distribution channel that is
not public — moat, or bridges shared directly between people, which is what the
QR sharing path is for.

It also means a thin webtunnel pool is the normal condition, not a fault to be
fixed. Selection has to assume most candidates are dead: probe before use,
retire on a verdict, and never let a preference for webtunnel imply that
webtunnel bridges will be available.

## Part of that yield was our own resolver, not the pool

The section above is right about the direction and was wrong about the
magnitude. Reading back the *reasons* a probe round recorded — rather than
just its verdicts — showed that most webtunnel "failures" were never about a
bridge. One round on a phone, sampled from the engine's log:

| reason | share | what it actually means |
| --- | --- | --- |
| `tcp connect: Network is unreachable` | 29% | the resolver returned AAAA; the device has no IPv6 route |
| `no DNS resolver available` | 24% | every DoH provider failed and system fallback is off |
| `DNS resolution timed out after 15s` | 15% | DoH starvation, see below |
| `webtunnel upgrade timed out` | 18% | plausibly the censor, or a dead host |
| a real verdict (HTTP 502, bad cert…) | 15% | genuinely not a bridge |

Two thirds of the pool was being condemned by our own name resolution. Three
mechanisms, all upstream of the bridge:

- **One address per name.** The resolver kept only the first record, often
  AAAA, and a device with no IPv6 route cannot dial it. Keeping the whole set
  and trying IPv4 first costs an instant `connect` failure instead of a bridge.
- **Fan-out that could not scale.** Every hostname raced all 18 DoH providers
  through 32 permits, each held up to four seconds. 425 hostnames is 7650
  queued lookups while a bridge waits fifteen seconds for its answer, so late
  bridges failed DNS unasked. Scoring providers by whether they answer — a
  property of the network, learned once — and racing only the best four fixed
  it.
- **A DNS failure was recorded as a bridge failure.** It is not evidence about
  the bridge; it now leaves the health record untouched, so an unresolvable
  host no longer walks a live bridge towards pruning or writes off its source
  as barren.

After the fix, on the same network and the same pool: webtunnel alive went from
**5 of 425 to 26 of 439**, and total alive across all transports from 760 to
814. `Network is unreachable` fell from 29% of failures to about 4%, and DNS
timeouts vanished from the sample. What now dominates is the upgrade timing out
— which is what a block, or a dead host, is supposed to look like.

The general lesson is worth more than the fix: a probe that only reports
pass/fail cannot be audited. Every one of these defects was invisible in the
verdicts and obvious in the reasons, and the health store had been recording
them as facts about bridges for weeks.

## Open direction

Client-side TLS ClientHello fragmentation (the zapret/GoodbyeDPI technique) is
the natural next step and composes with webtunnel rather than replacing it: it
prevents SNI-based blocking of the fronting domain and needs no cooperation
from the server.
