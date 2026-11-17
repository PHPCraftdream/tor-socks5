# tor-socks5-auth

SOCKS5 user accounts and password authentication for a proxy's SOCKS5 listener: Argon2id password hashing, an on-disk Ktav user registry, a runtime RFC 1929 verifier, and trust-on-first-use provisioning.

Built for SOCKS5 servers that authenticate humans rather than scripts. Passwords get a per-user salt and PHC serialisation; repeated successful logins are answered from a process-local HMAC-SHA256 cache bound to the hash snapshot, so the second login skips the expensive Argon2id pass — and failures are never cached, so brute-force attackers get no equivalent speed-up. An account whose stored hash is the `init` sentinel adopts the first non-empty password presented at login and persists the real hash back to disk.

## Usage

The crate publishes as `tor-socks5-auth` (`cargo add tor-socks5-auth`), while the library target keeps the in-tree name `auth` — so in code it is `use auth::…`.

```rust
use auth::{compute_hash, AuthState, User, UsersConfig};

// Argon2id: a PHC string in, a constant-work verify out.
let hash = compute_hash("alice-pass")?;

let registry = UsersConfig {
    users: vec![User {
        name: "alice".into(),
        hash,
        is_enabled: true,
        allowed_onion: false,
    }],
};

let state = AuthState::build(&registry)?;
// `state.verify(user, password)` answers RFC 1929 login attempts.
// A live angel uses `AuthState::build_persistent(cfg, users_path)`
// instead, so TOFU provisioning is written back to the registry.
```

The registry saves atomically (temp-file guard + rename) and lives next to the main config file, sharing its stem — `UsersConfig::resolve_path` derives the path.

## Administration

`Registry` edits the file the way the `users` command does: `add`, `add_init`, `remove`, `set_password`, `set_proxies`, `set_enabled`, `set_onion`. Each call is one transaction under the registry's cross-process lock (bounded wait, see `with_lock_wait`); Argon2id hashing happens before the lock is taken. It never prompts or prints: the password is an argument, and `ensure_absent` / `ensure_present` let a caller fail fast before it asks a human for one.

```rust
use auth::{Hop, NewUser, Registry, UsersConfig};

let registry = Registry::new(UsersConfig::resolve_path(config_path));
registry.add(NewUser { name: "alice".into(), ..NewUser::default() }, "alice-pass")?;
registry.set_onion("alice", true)?;
registry.set_proxies("alice", Hop::Pre, None)?; // inherit the global pool
```

## Example

`cargo run --example auth_flow -p tor-socks5-auth` runs the whole flow: hashing, a disabled account, an unknown one, an HMAC-cache hit, and a TOFU `init` adoption.
