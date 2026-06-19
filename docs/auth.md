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
