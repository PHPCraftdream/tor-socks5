//! Live authenticator with a success-cache and trust-on-first-use
//! (TOFU) password provisioning.
//!
//! * **HMAC success cache.** On every login attempt we first consult an
//!   in-memory HMAC cache: `HMAC-SHA256(server_secret, name || 0x00 ||
//!   password)` keyed by username. A constant-time match against a
//!   cached value lets us skip the expensive Argon2id verify. A miss
//!   falls through to the real verify; on success the cache is
//!   populated, on failure nothing is cached. Entries are bound to the
//!   PHC hash snapshot they were verified against: a snapshot mismatch
//!   is a cache miss and forces the real Argon2id verify, so hash
//!   rotation invalidates the cache structurally, and an in-flight
//!   verification that publishes its result late is harmless. `server_secret` is drawn from the OS RNG
//!   once per process — no persistence, so cache contents do not leak
//!   past a restart.
//!
//! * **TOFU via the `init` sentinel.** A user whose stored hash is the
//!   literal string [`INIT_SENTINEL`] (`"init"`) has not chosen a
//!   password yet. The first non-empty password presented for that
//!   account at login is accepted, hashed with Argon2id, and persisted
//!   to the user registry on disk — and only then is the login
//!   accepted and the credential cached. If the write-back fails, the
//!   login is refused, nothing is cached, and the account stays in
//!   `init`, still claimable by a later client. The registry write-lock
//!   is held across the state transition **and** the save, so
//!   concurrent resolutions of different `init` accounts cannot write
//!   an older snapshot over a newer one. Every writer of the registry —
//!   this TOFU write-back and every CLI `tor-socks5 users ...`
//!   mutation in another process — also holds a cross-process
//!   transaction lock ([`persist_lock::PathLock`], sibling
//!   `<users-file>.lock`) across its whole read-modify-write: the
//!   on-disk registry is re-read **under** that lock and the save
//!   publishes before it is released, so a concurrent CLI edit is
//!   serialised behind (or ahead of) the transition+save pair instead
//!   of being clobbered by a stale snapshot. The first connection to
//!   arrive wins; any concurrent
//!   connection offering a different password is then checked against
//!   the freshly set hash and rejected.

use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::Result;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use persist_lock::PathLock;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::compute_hash::{compute_hash, verify_hash};
use crate::users_config::UsersConfig;

type HmacSha256 = Hmac<Sha256>;

/// Stored-hash sentinel marking an account that has no password yet.
/// The first non-empty password seen at login is adopted (see the
/// module docs).
pub const INIT_SENTINEL: &str = "init";

/// A cached successful credential, bound to the exact PHC hash it was
/// verified against. If the account's authoritative hash changes, old
/// entries can never satisfy a new lookup (their snapshot differs), so
/// rotation invalidates the cache structurally — including for a
/// verification that was still in flight while the hash rotated and
/// publishes its result afterwards.
struct CacheEntry {
    hash_snapshot: String,
    hmac: [u8; 32],
}

/// Snapshot-style authenticator. Cheap to share between connections via
/// `Arc<AuthState>`; cache writes are lock-free (`DashMap`) and the
/// rarely-taken registry write-lock only fires when an `init` account
/// is being provisioned.
pub struct AuthState {
    /// Authoritative user list. Behind a lock because TOFU mutates a
    /// user's hash in place and we re-serialise the whole thing to disk.
    users: RwLock<UsersConfig>,
    /// `name -> (PHC hash snapshot, HMAC)` of the last accepted
    /// credential. Consulted before the real Argon2id verify; a hit
    /// requires both an HMAC match and an identical hash snapshot.
    cache: DashMap<String, CacheEntry>,
    /// Per-process random key for the cache HMAC.
    server_secret: [u8; 32],
    /// Where to persist the registry when an `init` account is
    /// resolved. `None` disables write-back (used in tests).
    users_path: Option<PathBuf>,
    /// Test-only hook invoked just before the registry save inside
    /// `resolve_init`, letting tests block a save or inject a save
    /// failure to force deterministic interleavings and error paths.
    /// Never present in production builds.
    #[cfg(test)]
    save_hook: std::sync::OnceLock<Box<dyn Fn() -> anyhow::Result<()> + Send + Sync>>,
    /// Test-only hook invoked immediately before the cross-process
    /// registry transaction lock is taken in `resolve_init` (after the
    /// password hash is computed), letting tests prove the lock ordering
    /// and edit the registry in the seam window. Never present in
    /// production builds.
    #[cfg(test)]
    lock_hook: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>>,
    /// Test-only hook invoked immediately before the Argon2id
    /// `verify_hash` call in `verify_with_cache`, letting tests park a
    /// verification at a deterministic point. Never present in
    /// production builds.
    #[cfg(test)]
    verify_hook: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl AuthState {
    /// Build an authenticator that does **not** persist TOFU writes.
    /// Intended for tests and callers that own no on-disk registry.
    pub fn build(cfg: &UsersConfig) -> Result<Self> {
        Self::build_inner(cfg, None)
    }

    /// Build an authenticator that writes resolved `init` passwords
    /// back to `users_path` (the live registry next to the main config).
    pub fn build_persistent(cfg: &UsersConfig, users_path: PathBuf) -> Result<Self> {
        Self::build_inner(cfg, Some(users_path))
    }

    fn build_inner(cfg: &UsersConfig, users_path: Option<PathBuf>) -> Result<Self> {
        let mut server_secret = [0u8; 32];
        getrandom::getrandom(&mut server_secret)
            .map_err(|e| anyhow::anyhow!("draw server_secret from OS RNG: {e}"))?;
        Ok(Self {
            users: RwLock::new(cfg.clone()),
            cache: DashMap::new(),
            server_secret,
            users_path,
            #[cfg(test)]
            save_hook: std::sync::OnceLock::new(),
            #[cfg(test)]
            lock_hook: std::sync::OnceLock::new(),
            #[cfg(test)]
            verify_hook: std::sync::OnceLock::new(),
        })
    }

    /// Test-only hook: install a callback invoked immediately before
    /// the Argon2id `verify_hash` call in `verify_with_cache`. The
    /// callback may block to force deterministic interleavings.
    #[cfg(test)]
    pub(crate) fn set_verify_hook(&self, f: Box<dyn Fn() + Send + Sync>) {
        let _ = self.verify_hook.set(f);
    }

    /// Test-only hook: install a callback invoked just before the
    /// registry save in `resolve_init` (inside the write-lock). The
    /// callback may block a save or inject a save failure (by returning
    /// `Err`), which is handled exactly like a real save error.
    #[cfg(test)]
    pub(crate) fn set_save_hook(&self, f: Box<dyn Fn() -> anyhow::Result<()> + Send + Sync>) {
        let _ = self.save_hook.set(f);
    }

    /// Test-only hook: install a callback invoked immediately before the
    /// cross-process registry transaction lock is acquired in
    /// `resolve_init`. The callback may block to force deterministic
    /// interleavings.
    #[cfg(test)]
    pub(crate) fn set_lock_hook(&self, f: Box<dyn Fn() + Send + Sync>) {
        let _ = self.lock_hook.set(f);
    }

    /// Number of users known to this authenticator.
    #[must_use]
    pub fn len(&self) -> usize {
        self.users
            .read()
            .expect("auth users lock poisoned")
            .users
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users
            .read()
            .expect("auth users lock poisoned")
            .users
            .is_empty()
    }

    /// True iff at least one user is known. The SOCKS5 server uses
    /// this to decide whether to advertise method `0x02` to the client.
    pub fn require_auth(&self) -> bool {
        !self.is_empty()
    }

    /// Whether the named account is permitted to open `.onion`
    /// connections. Returns `false` for an unknown or disabled account,
    /// so a `.onion` request from such an account is refused — same
    /// conservative default as the on-disk `allowed_onion: false`.
    pub fn allowed_onion(&self, name: &str) -> bool {
        self.users
            .read()
            .expect("auth users lock poisoned")
            .find(name)
            .is_some_and(|u| u.is_enabled && u.allowed_onion)
    }

    /// Run a login attempt for `(name, password)`. Returns `true` iff
    /// the credentials are accepted. Disabled accounts always return
    /// `false`, indistinguishable from an unknown username.
    pub fn verify(&self, name: &str, password: &str) -> bool {
        // Decide what to do under a short read-lock, then release it
        // before any expensive Argon2id work.
        enum Decision {
            Reject,
            Verify(String),
            Tofu,
        }
        let decision = {
            let guard = self.users.read().expect("auth users lock poisoned");
            match guard.find(name) {
                None => {
                    tracing::debug!(name = %name, "auth: unknown user");
                    Decision::Reject
                }
                Some(u) if !u.is_enabled => {
                    tracing::debug!(name = %name, "auth: disabled user");
                    Decision::Reject
                }
                Some(u) if u.hash == INIT_SENTINEL => Decision::Tofu,
                Some(u) => Decision::Verify(u.hash.clone()),
            }
        };

        match decision {
            Decision::Reject => false,
            Decision::Verify(hash) => self.verify_with_cache(name, password, &hash),
            Decision::Tofu => self.resolve_init(name, password),
        }
    }

    /// HMAC-cache fast path followed by the real Argon2id verify against
    /// `hash`. Cache entries are bound to the exact PHC hash snapshot
    /// they were verified against; a mismatching snapshot is a miss and
    /// forces the real verify (so rotation invalidates the cache, and a
    /// late-published in-flight verification is harmless). On success
    /// the cache is populated; failures are never cached.
    fn verify_with_cache(&self, name: &str, password: &str, hash: &str) -> bool {
        // Cache value is a stable function of (server_secret, name,
        // password) — constant-time-compared against a freshly computed
        // candidate so timing does not distinguish hit vs near-miss.
        let candidate = self.hmac(name, password);
        {
            if let Some(cached) = self.cache.get(name) {
                let entry = cached.value();
                // Plain == on the snapshot: both sides are process-local
                // registry strings, never attacker-chosen material.
                let snapshot_ok = entry.hash_snapshot == hash;
                if snapshot_ok && bool::from(entry.hmac.ct_eq(&candidate)) {
                    tracing::trace!(name = %name, "auth: cache hit");
                    return true;
                }
                tracing::trace!(name = %name, "auth: cache miss (mismatch)");
            }
        }

        #[cfg(test)]
        if let Some(hook) = self.verify_hook.get() {
            hook();
        }

        match verify_hash(hash, password) {
            Ok(true) => {
                self.cache.insert(
                    name.to_string(),
                    CacheEntry {
                        hash_snapshot: hash.to_string(),
                        hmac: candidate,
                    },
                );
                tracing::trace!(name = %name, "auth: cache populated");
                true
            }
            Ok(false) => {
                // Do NOT cache failures — caching them would let an
                // attacker run an offline-style attack at HMAC speed
                // instead of Argon2 speed.
                tracing::debug!(name = %name, "auth: bad password");
                false
            }
            Err(e) => {
                tracing::warn!(name = %name, error = %e, "auth: stored hash is malformed");
                false
            }
        }
    }

    /// Trust-on-first-use: the stored hash was the `init` sentinel.
    /// Adopt the first non-empty password, persist the real hash, and —
    /// only once the save is confirmed — populate the cache and accept
    /// the login.
    ///
    /// Concurrency contract: the Argon2id hash is computed **before** any
    /// lock is taken, so the critical section stays short. The
    /// cross-process registry transaction lock
    /// ([`persist_lock::PathLock`], sibling `<users-file>.lock`) is then
    /// held from the authoritative on-disk re-read through the publish,
    /// so a `tor-socks5 users ...` mutation in another process can never
    /// interleave inside this read-modify-write and be clobbered by our
    /// snapshot: the loser waits and builds on the winner's published
    /// state (TS17-07). The daemon takes that lock with a blocking wait —
    /// a refused login cannot be retried by the client, so the
    /// provisioning must not fail just because another writer happened to
    /// be mid-transaction. In-process, the registry write-lock is held
    /// across the transition and the save, which keeps concurrent
    /// resolutions of different `init` accounts monotonic. If anything
    /// fails (lock, re-read, save), the login is refused, memory and
    /// cache are left untouched, and the account remains in `init` and
    /// claimable by a later client.
    fn resolve_init(&self, name: &str, password: &str) -> bool {
        if password.is_empty() {
            tracing::debug!(name = %name, "auth: init account rejected empty password");
            return false;
        }
        // Compute the Argon2id hash before taking the write-lock. The
        // fsync below DOES now run inside the critical section — that is
        // intentional: init provisioning is a rare one-off event, and
        // serializing transition+save is exactly what makes concurrent
        // inits monotonic.
        let new_hash = match compute_hash(password) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(name = %name, error = %e, "auth: hashing init password failed");
                return false;
            }
        };
        // Cross-process transaction lock: held from the authoritative
        // re-read below through the save, so no CLI mutation in another
        // process can slip between our read and our publish (TS17-07).
        // Acquired BEFORE the in-process write lock; every registry
        // writer follows the same order, so the two lock domains cannot
        // cycle. Blocking acquire on purpose: see the doc comment.
        let file_lock = match &self.users_path {
            Some(path) => {
                #[cfg(test)]
                if let Some(hook) = self.lock_hook.get() {
                    hook();
                }
                match PathLock::acquire(path) {
                    Ok(lock) => Some(lock),
                    Err(e) => {
                        tracing::warn!(name = %name, error = %e, "auth: could not take the users registry transaction lock; refusing init login");
                        return false;
                    }
                }
            }
            None => None,
        };
        let mut guard = self.users.write().expect("auth users lock poisoned");

        // Build the authoritative "current" snapshot: the on-disk
        // registry when we persist, otherwise the in-memory one. Re-reading
        // picks up concurrent CLI edits made after this process started.
        let mut current = match &self.users_path {
            Some(path) => match UsersConfig::load(path) {
                Ok(cfg) => cfg,
                Err(e) => {
                    // Never clobber a file we could not read.
                    tracing::warn!(name = %name, error = %e, "auth: could not re-read users registry; refusing init login");
                    return false;
                }
            },
            None => guard.clone(),
        };

        // Checks on `current`, not on our possibly stale memory.
        match current.find(name) {
            None => {
                tracing::debug!(name = %name, "auth: init user vanished from registry");
                return false;
            }
            Some(u) if !u.is_enabled => {
                tracing::debug!(name = %name, "auth: disabled user");
                return false;
            }
            Some(u) if u.hash != INIT_SENTINEL => {
                // Lost the race: another connection in this process
                // provisioned the account, or a CLI `set-password` landed
                // meanwhile. Sync memory to the newer disk state and
                // verify against whatever credential won.
                let h = u.hash.clone();
                *guard = current;
                drop(guard);
                // Release the registry before the (potentially expensive) verify.
                drop(file_lock);
                return self.verify_with_cache(name, password, &h);
            }
            Some(_) => {}
        }

        // Transition on the authoritative snapshot.
        if let Some(u) = current.find_mut(name) {
            // Clone: the same snapshot string must go into the cache
            // entry below, bound to the hash committed to memory.
            u.hash = new_hash.clone();
        }

        // Persist FIRST; commit to memory and cache only after the save
        // is confirmed.
        if let Some(path) = &self.users_path {
            #[cfg(test)]
            if let Some(hook) = self.save_hook.get() {
                if let Err(e) = hook() {
                    tracing::warn!(name = %name, error = %e, "auth: init password NOT persisted; rejecting login so the account stays claimable");
                    return false;
                }
            }
            if let Err(e) = current.save(path) {
                tracing::warn!(name = %name, error = %e, "auth: init password NOT persisted; rejecting login so the account stays claimable");
                // guard drops without commit: memory keeps the old state.
                return false;
            }
            tracing::info!(name = %name, "auth: init password accepted and persisted");
        } else {
            tracing::info!(name = %name, "auth: init password accepted (no persistence configured)");
        }
        *guard = current;
        drop(guard);
        drop(file_lock);
        self.cache.insert(
            name.to_string(),
            CacheEntry {
                hash_snapshot: new_hash,
                hmac: self.hmac(name, password),
            },
        );
        true
    }

    fn hmac(&self, name: &str, password: &str) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(&self.server_secret).expect("HMAC accepts any key length");
        mac.update(name.as_bytes());
        mac.update(&[0x00]);
        mac.update(password.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        out
    }

    /// Test-only hook: how many entries are currently in the success
    /// cache. Behind `#[cfg(test)]` so it cannot accidentally leak into
    /// production code paths.
    #[cfg(test)]
    pub(crate) fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_hash::compute_hash;
    use crate::user::User;

    fn mk_user(name: &str, password: &str, enabled: bool) -> User {
        User {
            name: name.into(),
            hash: compute_hash(password).unwrap(),
            is_enabled: enabled,
            allowed_onion: false,
        }
    }

    fn init_user(name: &str) -> User {
        User {
            name: name.into(),
            hash: INIT_SENTINEL.into(),
            is_enabled: true,
            allowed_onion: false,
        }
    }

    fn state(users: Vec<User>) -> AuthState {
        AuthState::build(&UsersConfig { users }).unwrap()
    }

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tor-socks5-auth-state-test-{}-{}-{}",
            tag,
            std::process::id(),
            seq
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("users.ktav")
    }

    #[test]
    fn accepts_correct_password() {
        let s = state(vec![mk_user("alice", "secret", true)]);
        assert!(s.verify("alice", "secret"));
    }

    #[test]
    fn rejects_wrong_password() {
        let s = state(vec![mk_user("alice", "secret", true)]);
        assert!(!s.verify("alice", "WRONG"));
    }

    #[test]
    fn rejects_unknown_user() {
        let s = state(vec![mk_user("alice", "secret", true)]);
        assert!(!s.verify("mallory", "anything"));
    }

    #[test]
    fn rejects_disabled_user_silently() {
        let s = state(vec![mk_user("alice", "secret", false)]);
        assert!(
            !s.verify("alice", "secret"),
            "disabled even with right password"
        );
    }

    #[test]
    fn require_auth_is_false_for_empty_registry() {
        let s = state(vec![]);
        assert!(!s.require_auth());
    }

    #[test]
    fn require_auth_is_true_when_users_present() {
        let s = state(vec![mk_user("alice", "secret", true)]);
        assert!(s.require_auth());
    }

    #[test]
    fn first_successful_login_populates_cache_subsequent_hits_cache() {
        let s = state(vec![mk_user("alice", "secret", true)]);
        assert_eq!(s.cache_len(), 0);
        assert!(s.verify("alice", "secret"));
        assert_eq!(s.cache_len(), 1, "cache populated after first verify");
        // Second call should still succeed and not bump cache size.
        assert!(s.verify("alice", "secret"));
        assert_eq!(s.cache_len(), 1);
    }

    #[test]
    fn failed_logins_are_not_cached() {
        let s = state(vec![mk_user("alice", "secret", true)]);
        assert!(!s.verify("alice", "wrong-1"));
        assert!(!s.verify("alice", "wrong-2"));
        assert_eq!(s.cache_len(), 0, "failed attempts must not populate cache");
    }

    #[test]
    fn disabled_user_does_not_populate_cache() {
        let s = state(vec![mk_user("alice", "secret", false)]);
        assert!(!s.verify("alice", "secret"));
        assert_eq!(s.cache_len(), 0);
    }

    #[test]
    fn rotated_password_invalidates_cache_on_next_attempt() {
        let mut cfg = UsersConfig {
            users: vec![mk_user("alice", "secret", true)],
        };
        let s = AuthState::build(&cfg).unwrap();
        assert!(s.verify("alice", "secret"));
        assert_eq!(s.cache_len(), 1);

        // Simulate a password rotation and rebuild (the real proxy
        // re-builds on restart). The fresh server_secret means the same
        // plaintext computes a different HMAC anyway, but the key point
        // is that the old password must no longer be accepted.
        cfg.users[0].hash = compute_hash("rotated").unwrap();
        let s2 = AuthState::build(&cfg).unwrap();
        assert!(!s2.verify("alice", "secret"));
        assert!(s2.verify("alice", "rotated"));
    }

    #[test]
    fn empty_user_list_means_require_auth_false() {
        let s = state(vec![]);
        assert!(s.is_empty());
        assert!(!s.require_auth());
    }

    #[test]
    fn each_authstate_uses_a_distinct_server_secret() {
        let cfg = UsersConfig {
            users: vec![mk_user("alice", "secret", true)],
        };
        let s1 = AuthState::build(&cfg).unwrap();
        let s2 = AuthState::build(&cfg).unwrap();
        assert!(s1.verify("alice", "secret"));
        assert!(s2.verify("alice", "secret"));
        let v1 = s1.cache.get("alice").unwrap().hmac;
        let v2 = s2.cache.get("alice").unwrap().hmac;
        assert_ne!(
            v1, v2,
            "server_secret should not be deterministic across builds"
        );
    }

    // ------------------------------ TOFU init ------------------------------

    #[test]
    fn init_account_accepts_first_password_and_sets_real_hash() {
        let s = state(vec![init_user("alice")]);
        assert!(s.verify("alice", "chosen-pw"));
        // In-memory hash is now a real Argon2id PHC, not the sentinel.
        let stored = s.users.read().unwrap().find("alice").unwrap().hash.clone();
        assert!(
            stored.starts_with("$argon2id$"),
            "hash should be real now: {stored}"
        );
        assert!(verify_hash(&stored, "chosen-pw").unwrap());
        // And the credential is cached.
        assert_eq!(s.cache_len(), 1);
    }

    #[test]
    fn init_account_rejects_empty_password() {
        let s = state(vec![init_user("alice")]);
        assert!(
            !s.verify("alice", ""),
            "empty password must not claim the account"
        );
        let stored = s.users.read().unwrap().find("alice").unwrap().hash.clone();
        assert_eq!(stored, INIT_SENTINEL);
    }

    #[test]
    fn init_first_password_wins_second_different_password_rejected() {
        let s = state(vec![init_user("alice")]);
        assert!(s.verify("alice", "first"));
        // The account is now provisioned with "first"; a different
        // password must be rejected, the same one accepted.
        assert!(!s.verify("alice", "second"));
        assert!(s.verify("alice", "first"));
    }

    #[test]
    fn init_account_persists_real_hash_to_disk() {
        let path = tmp_path("persist");
        UsersConfig {
            users: vec![init_user("alice")],
        }
        .save(&path)
        .unwrap();

        let cfg = UsersConfig::load(&path).unwrap();
        let s = AuthState::build_persistent(&cfg, path.clone()).unwrap();
        assert!(s.verify("alice", "chosen-pw"));

        // Reload from disk: the sentinel must have been replaced by a
        // real hash that verifies the chosen password.
        let reloaded = UsersConfig::load(&path).unwrap();
        let stored = &reloaded.find("alice").unwrap().hash;
        assert_ne!(stored, INIT_SENTINEL);
        assert!(stored.starts_with("$argon2id$"));
        assert!(verify_hash(stored, "chosen-pw").unwrap());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn save_failure_does_not_confirm_init() {
        let path = tmp_path("savefail");
        // Real registry on disk with alice still in init.
        UsersConfig {
            users: vec![init_user("alice")],
        }
        .save(&path)
        .unwrap();
        let s =
            AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap();

        // Hook: the first TWO invocations inject a save failure (both
        // pw1 attempts must be rejected), later ones pass through so
        // pw2 can claim the account.
        let fails = std::sync::atomic::AtomicU32::new(2);
        s.set_save_hook(Box::new(move || {
            if fails.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                Err(anyhow::anyhow!("injected save failure"))
            } else {
                Ok(())
            }
        }));

        // TOFU path: injected save failure -> login refused, nothing cached.
        assert!(!s.verify("alice", "pw1"));
        assert_eq!(
            s.cache_len(),
            0,
            "failed save must not populate success cache"
        );
        // Still in init: the second attempt takes the TOFU path again.
        assert!(!s.verify("alice", "pw1"));
        assert_eq!(s.cache_len(), 0);

        // A DIFFERENT password now succeeds (hook passes through): this
        // proves the account was still in init — had pw1 been committed
        // despite the failure, this would be a lost-race verify against
        // pw1's hash and would return false. Note resolve_init re-reads
        // the disk file, which must STILL hold the init sentinel because
        // the failed attempts never wrote anything — that is exactly why
        // pw2 can claim the account.
        assert!(s.verify("alice", "pw2"));

        // Restart simulation: pw2 — never pw1 — is what landed on disk.
        let reloaded = UsersConfig::load(&path).unwrap();
        let hash = &reloaded.find("alice").unwrap().hash;
        assert_ne!(*hash, INIT_SENTINEL);
        assert!(verify_hash(hash, "pw2").unwrap());
        assert!(!verify_hash(hash, "pw1").unwrap());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn init_rejected_when_registry_unreadable_or_vanished() {
        // Part A: registry vanished/unreadable — a plain FILE where the
        // registry's parent directory should be, so load cannot see the
        // account on disk.
        let dir = tmp_path("vanished").parent().unwrap().to_path_buf();
        let blocker = dir.join("blocker");
        std::fs::File::create(&blocker).unwrap();
        let users_path = blocker.join("users.ktav");

        let s = AuthState::build_persistent(
            &UsersConfig {
                users: vec![init_user("alice")],
            },
            users_path.clone(),
        )
        .unwrap();
        // The registry cannot be read as containing the account, so the
        // login is refused (memory is not consulted for the transition).
        assert!(!s.verify("alice", "pw1"));
        assert_eq!(s.cache_len(), 0);
        let _ = std::fs::remove_dir_all(&dir);

        // Part B: registry present but corrupt — load() errors, so the
        // init transition must refuse rather than clobber the file.
        let path = tmp_path("corrupt");
        std::fs::write(&path, "not a ktav file {{{").unwrap();
        let s = AuthState::build_persistent(
            &UsersConfig {
                users: vec![init_user("alice")],
            },
            path.clone(),
        )
        .unwrap();
        assert!(!s.verify("alice", "pw1"));
        assert_eq!(s.cache_len(), 0);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn init_transition_incorporates_cli_edits() {
        let path = tmp_path("cli");
        UsersConfig {
            users: vec![init_user("alice")],
        }
        .save(&path)
        .unwrap();
        let st =
            AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap();

        // Simulate a concurrent CLI process (users_cli does
        // load -> mutate -> save in its own process): add "bob" with a
        // real hash after the daemon built its in-memory snapshot.
        let mut cli_cfg = UsersConfig::load(&path).unwrap();
        cli_cfg.users.push(mk_user("bob", "bobpw", true));
        cli_cfg.save(&path).unwrap();

        // The daemon's TOFU transition for alice must re-read the disk
        // registry and merge, not clobber.
        assert!(st.verify("alice", "alipw"));

        // Restart simulation: bob is intact, alice is resolved.
        let reloaded = UsersConfig::load(&path).unwrap();
        let bob = reloaded.find("bob").unwrap();
        assert!(
            verify_hash(&bob.hash, "bobpw").unwrap(),
            "bob not clobbered"
        );
        let alice = reloaded.find("alice").unwrap();
        assert_ne!(alice.hash, INIT_SENTINEL);
        assert!(verify_hash(&alice.hash, "alipw").unwrap());
        // Memory was refreshed to the merged disk state.
        assert_eq!(st.len(), 2);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    // ------------------------------ allowed_onion ------------------------------

    fn onion_user(name: &str, enabled: bool, allowed_onion: bool) -> User {
        User {
            name: name.into(),
            hash: compute_hash("pw").unwrap(),
            is_enabled: enabled,
            allowed_onion,
        }
    }

    #[test]
    fn allowed_onion_true_only_for_enabled_and_granted() {
        let s = state(vec![onion_user("alice", true, true)]);
        assert!(s.allowed_onion("alice"));
    }

    #[test]
    fn allowed_onion_false_when_not_granted() {
        let s = state(vec![onion_user("bob", true, false)]);
        assert!(!s.allowed_onion("bob"));
    }

    #[test]
    fn allowed_onion_false_for_disabled_even_if_granted() {
        let s = state(vec![onion_user("carol", false, true)]);
        assert!(
            !s.allowed_onion("carol"),
            "a disabled account must not reach onion even with the flag"
        );
    }

    #[test]
    fn allowed_onion_false_for_unknown_user() {
        let s = state(vec![onion_user("alice", true, true)]);
        assert!(!s.allowed_onion("nobody"));
    }

    #[test]
    fn init_account_disabled_is_not_provisioned() {
        let s = state(vec![User {
            name: "alice".into(),
            hash: INIT_SENTINEL.into(),
            is_enabled: false,
            allowed_onion: false,
        }]);
        assert!(!s.verify("alice", "chosen-pw"));
        let stored = s.users.read().unwrap().find("alice").unwrap().hash.clone();
        assert_eq!(
            stored, INIT_SENTINEL,
            "disabled init account stays unprovisioned"
        );
    }

    // --------------------------- cache snapshot binding ---------------------------

    #[test]
    fn stale_cache_rejected_after_tofu_reload_brings_rotated_hash() {
        let path = tmp_path("ts301-scenario");
        UsersConfig {
            users: vec![mk_user("alice", "oldpw", true), init_user("bob")],
        }
        .save(&path)
        .unwrap();
        let s = std::sync::Arc::new(
            AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap(),
        );

        // Prime the cache with alice's old credential.
        assert!(s.verify("alice", "oldpw"));
        assert_eq!(s.cache_len(), 1);

        // Simulate the CLI process rotating alice's password on disk.
        let mut cli_cfg = UsersConfig::load(&path).unwrap();
        cli_cfg.find_mut("alice").unwrap().hash = compute_hash("newpw").unwrap();
        cli_cfg.save(&path).unwrap();

        // TOFU login of bob pulls the rotated registry into memory.
        assert!(s.verify("bob", "bobpw"));

        // The stale cache entry must not resurrect the old password.
        assert!(
            !s.verify("alice", "oldpw"),
            "old password must be rejected after hash rotation"
        );
        assert!(s.verify("alice", "newpw"));

        // Disk state matches: the rotated hash verifies newpw only.
        let reloaded = UsersConfig::load(&path).unwrap();
        let alice = &reloaded.find("alice").unwrap().hash;
        assert!(verify_hash(alice, "newpw").unwrap());
        assert!(!verify_hash(alice, "oldpw").unwrap());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn late_in_flight_verify_cannot_reinstate_old_password_after_rotation() {
        let path = tmp_path("ts301-inflight");
        UsersConfig {
            users: vec![mk_user("alice", "oldpw", true), init_user("bob")],
        }
        .save(&path)
        .unwrap();
        let s = std::sync::Arc::new(
            AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap(),
        );

        // One-shot verify hook: on its first invocation signal the main
        // thread, then block until released (5s fail-safe timeout).
        // Later invocations pass through.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Arc::new(std::sync::Mutex::new(release_rx));
        let release_rx_hook = release_rx.clone();
        let fired = std::sync::atomic::AtomicBool::new(false);
        s.set_verify_hook(Box::new(move || {
            if !fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                tx.send(()).ok();
                let _ = release_rx_hook
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5));
            }
        }));

        // Thread A verifies against the OLD hash; it parks inside the
        // hook before the Argon2id work, holding no registry lock.
        let s_a = s.clone();
        let a = std::thread::spawn(move || s_a.verify("alice", "oldpw"));
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("hook fired: A is parked in verify");

        // While A is parked: CLI rotates alice on disk, then bob's TOFU
        // pulls the new registry into memory (bob takes the write lock
        // fine because A holds no lock).
        let mut cli_cfg = UsersConfig::load(&path).unwrap();
        cli_cfg.find_mut("alice").unwrap().hash = compute_hash("newpw").unwrap();
        cli_cfg.save(&path).unwrap();
        assert!(s.verify("bob", "bobpw"));

        // Release A: its check against the OLD hash legitimately
        // succeeds and publishes a cache entry with the OLD snapshot.
        release_tx.send(()).ok();
        assert!(
            a.join().unwrap(),
            "A's verification against the old hash snapshot succeeds"
        );

        // But the late-published entry must not accept the old password
        // now that the authoritative hash has rotated.
        assert!(
            !s.verify("alice", "oldpw"),
            "late-published cache entry must not accept the old password after rotation"
        );
        assert!(s.verify("alice", "newpw"));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
