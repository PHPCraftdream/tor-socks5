# tor-socks5-onion

v3 onion service address math and the vanity prefix-search core, without Tor. Addresses follow rend-spec-v3: `base32(PUBKEY(32) || CHECKSUM(2) || 0x03) + ".onion"`, where the checksum is the first two bytes of `SHA3-256(".onion checksum" || PUBKEY || 0x03)`. Keypairs are generated from a 32-byte seed (seed → SHA-512 → clamp → expanded secret key) or from the OS random number generator; the expanded secret key is kept zeroized and is never exposed through `Debug`.

The vanity search validates a base32 prefix target and compiles it to a bit pattern, so every attempt is a few bit instructions on the leading bytes of a fresh public key. The search itself runs on plain `std` threads, stops through an external `AtomicBool` cancel flag, and can publish the total attempts count into a shared progress counter. Helpers compute the expected number of attempts (32^len) and a rough wall-clock estimate for a measured generation rate.

The crate deliberately does **not** print, touch the network, link Tor, spawn runtimes or handle Ctrl-C: no stderr progress, no signal handling, no statics. That CLI behavior lives in the `socks5-proxy` binary — libraries stay silent.

## Usage

```rust
use tor_socks5_onion::address::{generate, parse_onion_address};
use tor_socks5_onion::vanity::{search, SearchOptions, VanityTarget};

let target = VanityTarget::new("a").unwrap();
let opts = SearchOptions { threads: 2, time_limit: None, ..Default::default() };
// `search` returns Found(Keypair) | TimedOut | Cancelled; pass a shared
// AtomicBool in `SearchOptions::cancel` for external cancellation.
let _ = (target, opts, search);
let _ = parse_onion_address(&generate().address());
```
