# Authentication

`tor-socks5` can require SOCKS5 clients to authenticate with a username and password
(RFC 1929). Authentication is **off** when no users are configured and **on** as soon as at
least one user exists.

## Storage

Accounts live in `tor-socks5.users.ktav`, next to the main config (same directory, same stem,
`.users.ktav` suffix). Each record:

```ktav
users: [
    { name: alice, hash: $argon2id$v=19$m=5120,t=2,p=1$...$..., is_enabled: true, allowed_onion: false }
    { name: bob,   hash: init,                                  is_enabled: true, allowed_onion: true }
]
```

- `hash` — an Argon2id PHC string, or the literal `init` sentinel (see TOFU below).
- `is_enabled` — a disabled account fails authentication **indistinguishably** from a missing
  one (no account-existence leak).
- `allowed_onion` — whether the account may open connections to `.onion` hidden services.
  **Defaults to `false`**; registry files written before this field existed load as `false`
  (see *Onion access* below).

Passwords are hashed with **Argon2id** (per-user random salt). The file is written atomically
(temp file + rename).

## Managing users

```bash
tor-socks5 users add <name>              # prompt for a password, store its Argon2id hash
tor-socks5 users add --init <name>       # create in trust-on-first-use mode (no password yet)
tor-socks5 users add --allow-onion <name> # add an account permitted to reach .onion
tor-socks5 users set-password <name>     # change the password
tor-socks5 users remove <name>
tor-socks5 users enable <name>
tor-socks5 users disable <name>
tor-socks5 users allow-onion <name>      # grant .onion access to an existing account
tor-socks5 users disallow-onion <name>   # revoke .onion access
tor-socks5 users list
```

All commands accept `--config <path>` to locate the registry. `--allow-onion` also works with
`--init` (`tor-socks5 users add --init --allow-onion <name>`).

## Onion access

The global `security.block_onion` policy is checked before account-level permissions. It defaults
to `true`, so new and legacy configurations refuse `.onion` destinations unless the operator
explicitly sets `security.block_onion: false`. With the global switch off, the per-account
`allowed_onion` rules below apply.

Each account carries an `allowed_onion` flag (**default `false`**). When a SOCKS5 CONNECT targets
a `.onion` hidden-service address, the proxy checks the **authenticated** account:

- account with `allowed_onion: true` (and enabled) → the onion connection proceeds;
- any other account → the connection is refused with SOCKS5 reply `0x02`
  (*connection not allowed by ruleset*); clearnet destinations are unaffected.

When **authentication is disabled** (no users configured), there is no account to gate on, so
anonymous clients are **unrestricted** — `.onion` works as usual. The gate only constrains
named accounts. Onion matching is on the final DNS label, case-insensitive, and tolerant of a
trailing FQDN dot.

## Trust on first use (`--init`)

An account whose stored `hash` is the literal `init` has **not chosen a password yet**. The
**first non-empty password** presented for that account at login is accepted, hashed with
Argon2id, and **written back to disk** as the real hash. The first connection to arrive wins;
a concurrent connection offering a different password is then checked against the freshly set
hash (and rejected if it differs).

This lets an operator provision accounts without handling plaintext passwords — hand out the
username, and the user's client sets the password on first connect.

Empty passwords never claim an `init` account.

## Verification performance

A successful `(name, password)` is remembered in a process-local **HMAC-SHA256 cache** keyed by
username, so repeated logins skip the expensive Argon2id verify. Failures are never cached, so a
brute-force attempt gains no speed-up. The Argon2id verify runs on a blocking thread pool, so it
never stalls the async runtime under a connection flood. The cache key is drawn from the OS RNG
once per process and is never persisted.

## Android (`packages/android-ffi`)

The Android JNI FFI crate (`libtorsocks5.so`) shares this exact authenticator with the CLI — same
`AuthState`, same Argon2id/HMAC-cache/TOFU semantics described above — but resolves its
configuration differently, since `nativeStart(configPath, callback)` is handed a config path by
the Kotlin side rather than discovering one via `--config`/`$TOR_SOCKS5_CONFIG`.

`proxy-config::Config` (the schema shared by the CLI and the FFI crate) carries an explicit,
serialisable `auth` section for this purpose:

```ktav
auth.enabled: true
auth.users_file: ""
```

- `auth.enabled` (default `true`) — master switch. Set to `false` to force anonymous NO_AUTH even
  if a users registry is present, without deleting it.
- `auth.users_file` (default `""`, meaning "not set") — optional explicit path to the
  `.users.ktav` registry. Empty falls back to the standard CLI convention:
  `auth::UsersConfig::resolve_path(configPath)` — same directory and filename stem as
  `configPath`, `.users.ktav` suffix (e.g. `configPath = ".../tor-socks5.ktav"` resolves to
  `.../tor-socks5.users.ktav`).

At `nativeStart`, the engine:

1. Loads `Config` from `configPath` as usual.
2. If `auth.enabled` is `false`, skips straight to anonymous NO_AUTH and logs that decision.
3. Otherwise resolves the registry path (`auth.users_file` if set, else the sibling-file
   convention above) and loads it with `auth::UsersConfig::load` — a missing file is **not** an
   error, it just means "no users configured".
4. If the registry is empty, the listener falls back to anonymous NO_AUTH (identical to the CLI's
   behaviour) — again logged explicitly, never silently.
5. Otherwise builds `auth::AuthState::build_persistent(&users, users_path)` (so a TOFU `init`
   account provisioned from an Android client gets its real hash written back to the same file)
   and requires RFC 1929 USER/PASS for every accepted connection.

Android differs from the CLI at step 4: an empty or missing registry is a startup error, not
anonymous access. This prevents a malformed or deleted registry from exposing the loopback proxy.

This decision is made once per `nativeStart` call and threaded through the accept loop
(`packages/android-ffi/src/engine.rs`) as `Option<Arc<AuthState>>`, passed to
`socks5_proto::handshake` exactly like the CLI path — there is no separate/weaker verification
code path for Android. Before this was wired up, `engine.rs` always called
`socks5_proto::handshake(&mut client, None)`, i.e. **any** `auth` configuration was ignored and
the Android SOCKS5 listener silently accepted unauthenticated connections regardless of what the
Kotlin side had configured. It now fails closed to NO_AUTH only when no users are configured (or
`auth.enabled: false`), and that fallback is always logged at `info` level so it is visible in
device logs, not a silent gap.

The exact Ktav key names for the users-registry file itself (`users:` array schema — see
*Storage* above) are unchanged; only the **Android-side pointer to that file** is new. Aligning
the on-device Kotlin config-writer with `auth.enabled`/`auth.users_file` is tracked as a follow-up
task on the `orbot` side.
