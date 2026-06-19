//! Live authenticator with a success-cache and trust-on-first-use
//! (TOFU) password provisioning.
//!
//! * **HMAC success cache.** On every login attempt we first consult an
//!   in-memory HMAC cache: `HMAC-SHA256(server_secret, name || 0x00 ||
//!   password)` keyed by username. A constant-time match against a
//!   cached value lets us skip the expensive Argon2id verify. A miss
//!   falls through to the real verify; on success the cache is
//!   populated, on failure nothing is cached (so brute-forcing gets no
//!   per-account speed-up). `server_secret` is drawn from the OS RNG
//!   once per process — no persistence, so cache contents do not leak
//!   past a restart.
//!
//! * **TOFU via the `init` sentinel.** A user whose stored hash is the
//!   literal string [`INIT_SENTINEL`] (`"init"`) has not chosen a
//!   password yet. The first non-empty password presented for that
//!   account at login is accepted, hashed with Argon2id, written back
//!   to the user registry on disk, and cached. The first connection to
//!   arrive wins; any concurrent connection offering a different
//!   password is then checked against the freshly set hash and
//!   rejected.

use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::Result;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::compute_hash::{compute_hash, verify_hash};
use crate::users_config::UsersConfig;

type HmacSha256 = Hmac<Sha256>;

/// Stored-hash sentinel marking an account that has no password yet.
/// The first non-empty password seen at login is adopted (see the
/// module docs).
pub const INIT_SENTINEL: &str = "init";

/// Snapshot-style authenticator. Cheap to share between connections via
/// `Arc<AuthState>`; cache writes are lock-free (`DashMap`) and the
/// rarely-taken registry write-lock only fires when an `init` account
/// is being provisioned.
pub struct AuthState {
    /// Authoritative user list. Behind a lock because TOFU mutates a
    /// user's hash in place and we re-serialise the whole thing to disk.
    users: RwLock<UsersConfig>,
    /// `name -> HMAC(server_secret, name || 0 || password)` of the last
    /// accepted credential. Consulted before the real Argon2id verify.
    cache: DashMap<String, [u8; 32]>,
    /// Per-process random key for the cache HMAC.
    server_secret: [u8; 32],
    /// Where to persist the registry when an `init` account is
    /// resolved. `None` disables write-back (used in tests).
    users_path: Option<PathBuf>,
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
        })
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
    /// `hash`. On success the cache is populated; failures are never
    /// cached.
    fn verify_with_cache(&self, name: &str, password: &str, hash: &str) -> bool {
        // Cache value is a stable function of (server_secret, name,
        // password) — constant-time-compared against a freshly computed
        // candidate so timing does not distinguish hit vs near-miss.
        let candidate = self.hmac(name, password);
        if let Some(cached) = self.cache.get(name) {
            if bool::from(cached.value().ct_eq(&candidate)) {
                tracing::trace!(name = %name, "auth: cache hit");
                return true;
            }
            tracing::trace!(name = %name, "auth: cache miss (mismatch)");
        }

        match verify_hash(hash, password) {
            Ok(true) => {
                self.cache.insert(name.to_string(), candidate);
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
    /// Adopt the first non-empty password, persist the real hash, and
    /// populate the cache. Concurrency-safe: the write-lock holder that
    /// finds the sentinel still set wins; a loser re-checks against the
    /// now-real hash.
    fn resolve_init(&self, name: &str, password: &str) -> bool {
        if password.is_empty() {
            tracing::debug!(name = %name, "auth: init account rejected empty password");
            return false;
        }
        // Compute the Argon2id hash BEFORE taking the write-lock so the
        // expensive work (and the later fsync) never runs inside the
        // critical section that every verify() read-locks.
        let new_hash = match compute_hash(password) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(name = %name, error = %e, "auth: hashing init password failed");
                return false;
            }
        };
        // Hold the write-lock only for the compare-and-set; clone a snapshot
        // to persist after releasing it.
        let snapshot = {
            let mut guard = self.users.write().expect("auth users lock poisoned");
            match guard.find(name) {
                Some(u) if !u.is_enabled => return false,
                Some(u) if u.hash != INIT_SENTINEL => {
                    // Lost the race: another connection already provisioned
                    // this account. Verify against whatever password won.
                    let h = u.hash.clone();
                    drop(guard);
                    return self.verify_with_cache(name, password, &h);
                }
                Some(_) => {}
                None => return false,
            }
            if let Some(u) = guard.find_mut(name) {
                u.hash = new_hash;
            }
            guard.clone() // cheap relative to Argon2; persist without the lock
        };
        if let Some(path) = &self.users_path {
            match snapshot.save(path) {
                Ok(()) => {
                    tracing::info!(name = %name, "auth: init password accepted and persisted")
                }
                Err(e) => {
                    tracing::warn!(name = %name, error = %e, "auth: init password set in memory but could NOT be persisted")
                }
            }
        } else {
            tracing::info!(name = %name, "auth: init password accepted (no persistence configured)");
        }
        self.cache
            .insert(name.to_string(), self.hmac(name, password));
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
        let v1 = *s1.cache.get("alice").unwrap();
        let v2 = *s2.cache.get("alice").unwrap();
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
}
