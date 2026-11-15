# tor-socks5-onion

v3 onion service address math and the vanity prefix-search core, without Tor. Addresses follow rend-spec-v3: `base32(PUBKEY(32) || CHECKSUM(2) || 0x03) + ".onion"`, where the checksum is the first two bytes of `SHA3-256(".onion checksum" || PUBKEY || 0x03)`. Keypairs are generated from a 32-byte seed (seed → SHA-512 → clamp → expanded secret key) or from the OS random number generator; the expanded secret key is kept zeroized and is never exposed through `Debug`.

The vanity search validates a base32 prefix target and compiles it to a bit pattern, so every attempt is a few bit instructions on the leading bytes of a fresh public key. The search itself runs on plain `std` threads, stops through an external `AtomicBool` cancel flag, and can publish the total attempts count into a shared progress counter. Helpers compute the expected number of attempts (32^len) and a rough wall-clock estimate for a measured generation rate.

The crate deliberately does **not** print, touch the network, link Tor, spawn runtimes or handle Ctrl-C: no stderr progress, no signal handling, no statics. That CLI behavior lives in the `socks5-proxy` binary — libraries stay silent.

## Onion identity keystore (`keys` feature)

Behind the `keys` feature the crate adds onion **identity** management on top of the Arti native keystore (`tor-keymgr`/`tor-hscrypto` only — no Tor client, no patch-kit):

- `store` reads and writes identity keys exclusively through tor-keymgr; the on-disk key format is never hand-rolled. The keystore directory is always an explicit argument — the crate never derives it from a config path.
- `identity` settles identities at launch: the onion services file (`<stem>.onion.ktav`) is the source of truth, and the keystore (a copy) is brought to the key the file holds, in one batched rewrite.
- `ops` holds the command cores `create_service`, `list_services`, `show_service`, `export_identity`, `import_identity` and `remove_service`. The portable export format is simply the keystore's own key-file bytes. The `HsIdKeypairSpecifier`/`HsIdPublicKeySpecifier` types repeat `tor-hsservice`'s declarations with the same prefix/role, so keys land at the paths arti reads.
- Typed errors (`KeysError`) keep the established command messages; printing, prompting, confirmations (`--force`/`--yes`) and port-string parsing stay with the application.

```rust,ignore
use tor_socks5_onion::keys;

let lock = keys::lock(keystore_dir)?; // refuse while the server runs
let recorded = keys::create_service(config_path, keystore_dir, "web", None, false,
                                    keys::NewIdentity::Random)?;
println!("{}", recorded.address);
```

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
