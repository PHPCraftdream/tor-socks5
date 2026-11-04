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
//!   `init`, still claimable by a later client.
//!   Публикация и сохранение сериализованы через gate, поэтому
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

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::{OwnedRwLockReadGuard, RwLock as AsyncRwLock};

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

/// Подтверждение учётных данных, привязанное к экземпляру и снимку.
pub struct CredentialProof {
    issuer: Arc<()>,
    generation: Arc<()>,
    name: String,
}

impl CredentialProof {
    /// Имя подтверждённой учётки.
    pub fn username(&self) -> &str {
        &self.name
    }
}

/// Политика снимка; удерживайте lease до завершения подключения.
#[must_use = "lease удерживает публикацию до завершения подключения"]
pub struct AdmissionLease {
    _guard: OwnedRwLockReadGuard<()>,
    name: String,
    allowed_onion: bool,
    allowed_clients: Option<client_acl::AllowedClients>,
    pre_socks5: Option<client_acl::EndpointOverride>,
    post_socks5: Option<client_acl::EndpointOverride>,
}

impl AdmissionLease {
    /// Имя учётки.
    pub fn username(&self) -> &str {
        &self.name
    }
    /// Доступ к onion.
    pub fn allowed_onion(&self) -> bool {
        self.allowed_onion
    }
    /// ACL клиента; None означает отсутствие ограничений.
    pub fn allowed_clients(&self) -> Option<&client_acl::AllowedClients> {
        self.allowed_clients.as_ref()
    }
    /// Маршрут до Tor.
    pub fn pre_socks5(&self) -> Option<&client_acl::EndpointOverride> {
        self.pre_socks5.as_ref()
    }
    /// Маршрут после Tor.
    pub fn post_socks5(&self) -> Option<&client_acl::EndpointOverride> {
        self.post_socks5.as_ref()
    }
}

struct Snapshot {
    config: UsersConfig,
    generation: Arc<()>,
}
impl std::ops::Deref for Snapshot {
    type Target = UsersConfig;
    fn deref(&self) -> &UsersConfig {
        &self.config
    }
}

/// Snapshot-style authenticator. Cheap to share between connections via
/// `Arc<AuthState>`; cache writes are lock-free (`DashMap`) and the
/// rarely-taken registry write-lock only fires when an `init` account
/// is being provisioned.
pub struct AuthState {
    /// Authoritative user list. Behind a lock because TOFU mutates a
    /// user's hash in place and we re-serialise the whole thing to disk.
    users: RwLock<Snapshot>,
    issuer: Arc<()>,
    gate: Arc<AsyncRwLock<()>>,
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
            users: RwLock::new(Snapshot {
                config: cfg.clone(),
                generation: Arc::new(()),
            }),
            issuer: Arc::new(()),
            gate: Arc::new(AsyncRwLock::new(())),
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

    /// Вызывается перед сохранением под gate; только для тестов.
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

    /// True when this authenticator knows no users. Inverse of
    /// [`len`](Self::len); [`require_auth`](Self::require_auth) is just
    /// its negation.
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

    /// Разрешён ли peer `peer` по per-user ACL учётки `name`. Метод всегда
    /// fail-closed по lookup: пользователь отсутствует в текущем snapshot
    /// ИЛИ `is_enabled == false` => `false` (в т.ч. при пустом реестре —
    /// fail-open исключение для no-auth выбирает CALLER по configured auth
    /// `None`, не по содержимому snapshot). Один read-guard — без двойного
    /// lock TOCTOU. `None`-политика — без ограничений.
    /// IPv4-mapped IPv6-пир (`::ffff:a.b.c.d`) нормализует уже
    /// `AllowedClients::allows`, здесь повторной нормализации нет.
    pub fn client_allowed(&self, name: &str, peer: IpAddr) -> bool {
        let guard = self.users.read().expect("auth users lock poisoned");
        let Some(u) = guard.find(name).filter(|u| u.is_enabled) else {
            return false;
        };
        match u.allowed_clients.as_ref() {
            Some(policy) => policy.allows(peer),
            None => true,
        }
    }

    /// Проверка только в блокирующем потоке; TOFU может ждать диск и gate.
    /// Отмена вызывающей задачи не отменяет уже запущенную блокирующую работу.
    pub fn verify(&self, name: &str, password: &str) -> bool {
        self.verify_proof(name, password).is_some()
    }

    /// Проверка в блокирующем потоке с привязкой к снимку.
    pub fn verify_proof(&self, name: &str, password: &str) -> Option<CredentialProof> {
        let (hash, generation) = {
            let guard = self.users.read().expect("auth users lock poisoned");
            let user = guard.find(name).filter(|u| u.is_enabled)?;
            (user.hash.clone(), guard.generation.clone())
        };
        let generation = if hash == INIT_SENTINEL {
            self.resolve_init(name, password)?
        } else if self.verify_with_cache(name, password, &hash) {
            generation
        } else {
            return None;
        };
        Some(CredentialProof {
            issuer: self.issuer.clone(),
            generation,
            name: name.to_owned(),
        })
    }

    /// Перечитывает диск только в блокирующем потоке: PathLock → gate → users.
    /// Чтение выполняется под обоими замками; ошибка не меняет снимок.
    /// Отсутствующий путь — ошибка; отсутствующий файл означает пустой реестр.
    pub fn reload(&self) -> Result<()> {
        let path = self
            .users_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("путь реестра не задан"))?;
        let _file_lock = PathLock::acquire(path)?;
        let _gate = self.gate.blocking_write();
        let config = UsersConfig::load(path)?;
        self.publish(config);
        Ok(())
    }

    #[cfg(test)]
    fn replace_snapshot(&self, cfg: &UsersConfig) {
        let _gate = self.gate.blocking_write();
        self.publish(cfg.clone());
    }

    fn publish(&self, config: UsersConfig) -> Arc<()> {
        let generation = Arc::new(());
        *self.users.write().expect("auth users lock poisoned") = Snapshot {
            config,
            generation: generation.clone(),
        };
        generation
    }

    /// Проверяет proof и выдаёт lease, удерживаемый до завершения dial.
    /// Отмена ожидания освобождает очередь; сброс lease освобождает gate.
    /// Публикация ждёт lease; после неё старый proof не допускается.
    /// Уже завершённые подключения публикация не отзывает.
    pub async fn admit(&self, proof: &CredentialProof) -> Option<AdmissionLease> {
        let gate = self.gate.clone().read_owned().await;
        let snapshot = self.users.read().expect("auth users lock poisoned");
        if !Arc::ptr_eq(&proof.issuer, &self.issuer)
            || !Arc::ptr_eq(&proof.generation, &snapshot.generation)
        {
            return None;
        }
        let user = snapshot.find(&proof.name).filter(|u| u.is_enabled)?;
        Some(AdmissionLease {
            _guard: gate,
            name: proof.name.clone(),
            allowed_onion: user.allowed_onion,
            allowed_clients: user.allowed_clients.clone(),
            pre_socks5: user.pre_socks5.clone(),
            post_socks5: user.post_socks5.clone(),
        })
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

    /// TOFU: PathLock, gate, users; только блокирующий поток.
    fn resolve_init(&self, name: &str, password: &str) -> Option<Arc<()>> {
        if password.is_empty() {
            tracing::debug!(name = %name, "auth: init account rejected empty password");
            return None;
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
                return None;
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
                        return None;
                    }
                }
            }
            None => None,
        };
        let gate = self.gate.blocking_write();

        // Build the authoritative "current" snapshot: the on-disk
        // registry when we persist, otherwise the in-memory one. Re-reading
        // picks up concurrent CLI edits made after this process started.
        let mut current = match &self.users_path {
            Some(path) => match UsersConfig::load(path) {
                Ok(cfg) => cfg,
                Err(e) => {
                    // Never clobber a file we could not read.
                    tracing::warn!(name = %name, error = %e, "auth: could not re-read users registry; refusing init login");
                    return None;
                }
            },
            None => self
                .users
                .read()
                .expect("auth users lock poisoned")
                .config
                .clone(),
        };

        // Checks on `current`, not on our possibly stale memory.
        match current.find(name) {
            None => {
                tracing::debug!(name = %name, "auth: init user vanished from registry");
                return None;
            }
            Some(u) if !u.is_enabled => {
                tracing::debug!(name = %name, "auth: disabled user");
                return None;
            }
            Some(u) if u.hash != INIT_SENTINEL => {
                // Lost the race: another connection in this process
                // provisioned the account, or a CLI `set-password` landed
                // meanwhile. Sync memory to the newer disk state and
                // verify against whatever credential won.
                let h = u.hash.clone();
                let generation = self.publish(current);
                drop(gate);
                // Release the registry before the (potentially expensive) verify.
                drop(file_lock);
                return self
                    .verify_with_cache(name, password, &h)
                    .then_some(generation);
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
                    return None;
                }
            }
            if let Err(e) = current.save(path) {
                tracing::warn!(name = %name, error = %e, "auth: init password NOT persisted; rejecting login so the account stays claimable");
                // Ошибка сохранения не меняет снимок в памяти.
                return None;
            }
            tracing::info!(name = %name, "auth: init password accepted and persisted");
        } else {
            tracing::info!(name = %name, "auth: init password accepted (no persistence configured)");
        }
        let generation = self.publish(current);
        drop(gate);
        drop(file_lock);
        self.cache.insert(
            name.to_string(),
            CacheEntry {
                hash_snapshot: new_hash,
                hmac: self.hmac(name, password),
            },
        );
        Some(generation)
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
mod contract_tests;
#[cfg(test)]
mod tests;
