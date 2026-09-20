//! Persistent, TTL-aware cache of [`ResolvedAnswer`]s keyed by hostname.
//!
//! Answers are resolved through DoH (see [`crate::doh_client`]) and cached so a
//! restart — or the next query for an already-seen name — does not pay the
//! Tor-tunnel round trip again. Two properties shape the design:
//!
//! * **Wall-clock expiry survives restarts.** An entry is fresh while
//!   `resolved_at + ttl` is still in the future, computed in whole unix
//!   seconds with saturating arithmetic (a nonsense stamp can never overflow
//!   into a panic or an unexpiry). Because both stamps are wall-clock, an
//!   entry saved to disk and loaded back keeps exactly the lifetime it had —
//!   a save can never rejuvenate an answer. On disk the timestamps have
//!   whole-second precision (a sub-second `resolved_at` is truncated, which
//!   can only make an entry expire *earlier*, never later), and sub-second
//!   TTLs are likewise truncated to seconds.
//! * **Disk IO is best-effort and atomic.** [`DnsCache::load`] treats a
//!   missing, unreadable, or half-corrupt file as an empty cache — the cache
//!   simply warms up from DoH instead — while [`DnsCache::save`] publishes a
//!   whole file atomically on top of [`persist_lock::TempFileGuard`]: the
//!   content is staged in a lock-owned temp file, fsynced, and renamed onto
//!   the target, so a reader (or the next boot's loader) sees either the old
//!   file or the new one, never a torn one. On any error the guard's `Drop`
//!   removes the temp.
//!
//! The on-disk format is plain text, one line per host (see [`format_line`]),
//! in the spirit of this codebase's other file-based persistence (e.g.
//! bridge-probe's persisted DNS fallback) rather than pulling in a
//! serialization dependency for four fields.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use time::OffsetDateTime;

use crate::error::DnsServerError;
use crate::types::ResolvedAnswer;

/// Bound on remembered hosts. The resolver only ever asks about names that
/// appear in a (finite) bridge or provider list, but that list is refreshed
/// at runtime and entries for names that left it should not accumulate for
/// the life of a VPN session. Generous next to any real bridge list; small
/// next to the megabyte-scale whole-file saves.
pub const DNS_CACHE_CAP: usize = 4096;

/// Persistent, TTL-aware cache of resolved answers.
///
/// Shared interior state behind locks; every method takes `&self`. The
/// `entries` lock is the only lock most callers ever touch. `save_lock`
/// serialises one save's whole snapshot→publish span per instance (see
/// [`DnsCache::save`]); `save_seq` hands [`persist_lock::TempFileGuard`]
/// the unique-per-instance sequence number its temp-file naming needs.
pub struct DnsCache {
    /// Hostname → last fresh answer. Lock discipline: every access goes
    /// through `.lock().unwrap_or_else(|p| p.into_inner())` — a poisoned
    /// lock still holds valid entries, so panic in one thread must not take
    /// the cache down.
    entries: Mutex<HashMap<String, ResolvedAnswer>>,
    /// Sequence number for `TempFileGuard::create` temp names, bumped per
    /// save so two saves from one instance never collide on a temp name.
    save_seq: AtomicU64,
    /// Serialises save→publish per instance. Locked before the save's
    /// snapshot is taken and held until the temp file has been renamed onto
    /// the target, so a later save cannot snapshot — and therefore cannot
    /// publish — anything older than what is already on disk. Deliberately
    /// a tokio mutex, not a std one: the guard must live across the save's
    /// only `.await` (the `spawn_blocking` join), and a
    /// `std::sync::MutexGuard` is `!Send`, which poisons the future
    /// (E0277) and cannot be moved into a `'static` closure either (E0521).
    /// The tokio mutex is async-aware, so a queued save parks its task
    /// instead of blocking a worker thread.
    save_lock: tokio::sync::Mutex<()>,
}

impl DnsCache {
    /// An empty cache.
    pub fn new() -> Self {
        DnsCache {
            entries: Mutex::new(HashMap::new()),
            save_seq: AtomicU64::new(0),
            save_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The fresh answer for `host`, if one is cached.
    ///
    /// Fresh means `resolved_at + ttl` is still in the future (whole unix
    /// seconds, saturating). An expired entry is treated as absent *and
    /// removed on access* — lazy removal: expired entries cost nothing
    /// until someone asks, and no background sweeper is needed.
    pub fn get(&self, host: &str) -> Option<ResolvedAnswer> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_unix();
        match entries.get(host) {
            Some(answer) if is_fresh(answer, now) => Some(answer.clone()),
            // Absent, or present but stale: stale ones are dropped here so
            // `len()` does not keep counting dead entries forever.
            Some(_) => {
                entries.remove(host);
                None
            }
            None => None,
        }
    }

    /// Remember `answer` for `host`, subject to [`DNS_CACHE_CAP`].
    ///
    /// When the cache is already at the cap: first the expired entries are
    /// swept, then — if that was not enough — the entries soonest to expire
    /// are evicted (they have the least left to give). The entry being
    /// inserted is never the eviction victim, and `len()` is guaranteed to
    /// be `<= DNS_CACHE_CAP` after the insert. No freshness check happens
    /// here; [`DnsCache::get`] is the freshness gate.
    pub fn insert(&self, host: &str, answer: ResolvedAnswer) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if entries.len() >= DNS_CACHE_CAP {
            // Sweep the dead first: after a quiet period this alone frees
            // room, and expired entries must not displace fresh ones.
            let now = now_unix();
            entries.retain(|_, existing| is_fresh(existing, now));
            // Still full: shed the entries soonest to expire. The one we
            // are about to insert is excluded — it must never be the
            // victim of the eviction that makes room for it.
            let overflow = entries.len().saturating_sub(DNS_CACHE_CAP - 1);
            if overflow > 0 {
                let mut by_expiry: Vec<(String, i64)> = entries
                    .iter()
                    .filter(|(existing_host, _)| existing_host.as_str() != host)
                    .map(|(existing_host, existing)| {
                        (existing_host.clone(), expires_at_unix(existing))
                    })
                    .collect();
                by_expiry.sort_by_key(|(_, expires_at)| *expires_at);
                for (victim, _) in by_expiry.into_iter().take(overflow) {
                    entries.remove(&victim);
                }
            }
        }
        entries.insert(host.to_owned(), answer);
    }

    /// How many hosts are currently remembered (including expired-but-not-
    /// yet-swept entries — they leave the count on access, on save, or on
    /// cap pressure).
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Whether no host is currently remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Best-effort constructor: load a previously saved cache from `path`.
    ///
    /// The disk read is blocking file IO, so it runs on Tokio's blocking
    /// pool, never on an async worker. Any leftover temp files from dead
    /// writers are swept first (best-effort, via
    /// `persist_lock::cleanup_temp_files`). A missing, unreadable, or
    /// half-corrupt file means an **empty** cache, not an error — the cache
    /// is an optimisation and simply warms up from DoH again — and
    /// malformed lines are skipped without panicking. Later duplicate
    /// entries overwrite earlier ones (the loader builds a fresh map).
    pub async fn load(path: &Path) -> DnsCache {
        let path = path.to_owned();
        let entries = tokio::task::spawn_blocking(move || load_entries_from_disk(&path))
            .await
            // A blocking job that fails to join is as good as an unreadable
            // file: start empty.
            .unwrap_or_default();
        DnsCache {
            entries: Mutex::new(entries),
            save_seq: AtomicU64::new(0),
            save_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Atomically publish the fresh portion of the cache to `path`.
    ///
    /// Only fresh entries are written — a periodic save can never re-stamp a
    /// long-expired entry into looking freshly resolved. The snapshot is
    /// cloned under the `entries` lock and the lock guard is dropped before
    /// any await, so queries never wait on disk IO.
    ///
    /// The per-instance `save_lock` is taken *before* the snapshot and held
    /// across the whole snapshot→format→write→fsync→rename span (i.e. across
    /// the `spawn_blocking` join below) — this is bridge-probe's generation
    /// protocol reduced to what a per-instance cache needs: a later save
    /// cannot start snapshotting until the earlier one has finished
    /// renaming, so an older snapshot can never overwrite a newer one and no
    /// rollback is possible. The guard stays in the parent and never enters
    /// the `'static` closure (a guard borrowed from `self` cannot be moved
    /// into it).
    ///
    /// Publication goes through [`persist_lock::TempFileGuard`]: temp file,
    /// fsync, atomic rename onto the target. An empty cache publishes an
    /// empty file — that is correct. Every IO error is reported as
    /// [`DnsServerError::CacheIo`] with `op: "save"`; a panicked save task
    /// is wrapped the same way.
    pub async fn save(&self, path: &Path) -> Result<(), DnsServerError> {
        // Save critical section: taken before the snapshot, released when
        // this future finishes (after the publish below has resolved).
        let _save_guard = self.save_lock.lock().await;
        let now = now_unix();
        let snapshot: Vec<(String, ResolvedAnswer)> = {
            let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
            entries
                .iter()
                .filter(|(_, answer)| is_fresh(answer, now))
                .map(|(host, answer)| (host.clone(), answer.clone()))
                .collect()
        };
        let path = path.to_owned();
        let seq = self.save_seq.fetch_add(1, Ordering::Relaxed);
        let publish = move || {
            let lines: Vec<String> = snapshot
                .iter()
                .map(|(host, answer)| format_line(host, answer))
                .collect();
            let mut contents = lines.join("\n");
            if !lines.is_empty() {
                contents.push('\n');
            }
            let mut temp = persist_lock::TempFileGuard::create(&path, seq)?;
            // On any error below, the guard's Drop removes the temp file.
            temp.write_all(contents.as_bytes())?;
            temp.fsync()?;
            temp.rename_into_target()
        };
        match tokio::task::spawn_blocking(publish).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(DnsServerError::CacheIo { op: "save", source }),
            Err(join_error) => Err(DnsServerError::CacheIo {
                op: "save",
                source: std::io::Error::other(format!(
                    "dns cache save task panicked: {join_error}"
                )),
            }),
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        DnsCache::new()
    }
}

/// Whole unix seconds right now. The cache's entire notion of time is
/// whole-second wall-clock stamps (see the module docs).
fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// Whether `answer` is still servable at `now_unix`: its `resolved_at + ttl`
/// lies in the future. Saturating on purpose — a huge TTL or a stamp at the
/// edge of the representable range must saturate, never panic and never wrap
/// into a false "expired".
fn is_fresh(answer: &ResolvedAnswer, now_unix: i64) -> bool {
    expires_at_unix(answer) > now_unix
}

/// When `answer` stops being servable, in whole unix seconds. Also the
/// eviction sort key: at cap pressure the entries soonest to this moment are
/// shed first.
fn expires_at_unix(answer: &ResolvedAnswer) -> i64 {
    // `i64::try_from` rather than `as i64`: a `u64` count above `i64::MAX`
    // would wrap into a negative (negative-TTL!) number under `as`; try_from
    // saturates such absurd TTLs at `i64::MAX` instead.
    let ttl_secs = i64::try_from(answer.ttl.as_secs()).unwrap_or(i64::MAX);
    answer.resolved_at.unix_timestamp().saturating_add(ttl_secs)
}

/// One line per host: `host\tip1,ip2,...\tttl_secs\tresolved_at_unix`.
/// Plain text, matching this codebase's other file-based persistence (see
/// bridge-probe's `format_persisted_line`) rather than pulling in a
/// serialization dependency for four fields.
fn format_line(host: &str, answer: &ResolvedAnswer) -> String {
    use std::fmt::Write as _;

    // One growing String instead of a Vec<String> per address list: the
    // persist path formats every entry on every save.
    let mut line = String::with_capacity(host.len() + 32 + answer.addrs.len() * 16);
    line.push_str(host);
    line.push('\t');
    for (index, addr) in answer.addrs.iter().enumerate() {
        if index > 0 {
            line.push(',');
        }
        let _ = write!(line, "{addr}");
    }
    line.push('\t');
    let _ = write!(line, "{}", answer.ttl.as_secs());
    line.push('\t');
    // Whole-second precision on disk: truncating a sub-second `resolved_at`
    // can only move expiry earlier, never later.
    let _ = write!(line, "{}", answer.resolved_at.unix_timestamp());
    line
}

/// Inverse of [`format_line`]; `None` for any malformed line — wrong field
/// count, empty host, empty or partially-unparseable address list, bad ttl
/// or timestamp — and callers treat `None` as "skip line". Never panics on
/// arbitrary input. The stamp is `i64`, so pre-1970 stamps parse fine.
fn parse_line(line: &str) -> Option<(String, ResolvedAnswer)> {
    let mut parts = line.splitn(4, '\t');
    let host = parts.next()?.to_owned();
    if host.is_empty() {
        return None;
    }
    let addr_field = parts.next()?;
    let mut addrs: Vec<IpAddr> = Vec::new();
    for part in addr_field.split(',') {
        // `?` on every component: one bad address rejects the whole line
        // rather than silently keeping a truncated list.
        addrs.push(part.parse().ok()?);
    }
    if addrs.is_empty() {
        return None;
    }
    let ttl_secs: u64 = parts.next()?.trim().parse().ok()?;
    let stamp: i64 = parts.next()?.trim().parse().ok()?;
    let resolved_at = OffsetDateTime::from_unix_timestamp(stamp).ok()?;
    Some((
        host,
        ResolvedAnswer {
            addrs,
            ttl: Duration::from_secs(ttl_secs),
            resolved_at,
        },
    ))
}

/// Blocking half of [`DnsCache::load`]: sweep dead writers' temp files
/// (best-effort), read the file, parse every well-formed line. Missing or
/// unreadable file → empty map. Runs on the blocking pool only.
fn load_entries_from_disk(path: &Path) -> HashMap<String, ResolvedAnswer> {
    persist_lock::cleanup_temp_files(path);
    let Ok(data) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    let mut entries = HashMap::new();
    for line in data.lines() {
        if let Some((host, answer)) = parse_line(line) {
            entries.insert(host, answer);
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;

    /// Scratch dir per test: temp_dir + pid + atomic seq, per the
    /// bridge-store `tmp_dir()` pattern (no tempfile crate).
    fn tmp_dir() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tor-socks5-dns-cache-test-{}-{}",
            std::process::id(),
            seq
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Whole-second stamp from a unix timestamp, so `ResolvedAnswer`
    /// equality (which includes nanoseconds) is exact across a disk
    /// round-trip.
    fn stamp(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    fn answer(ttl: Duration, resolved_at: OffsetDateTime, addrs: &[&str]) -> ResolvedAnswer {
        ResolvedAnswer {
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            ttl,
            resolved_at,
        }
    }

    // -- get / insert --------------------------------------------------------

    #[test]
    fn insert_then_get_returns_same_answer() {
        let cache = DnsCache::new();
        let fresh = answer(Duration::from_secs(3600), stamp(now()), &["1.2.3.4"]);
        cache.insert("example.com", fresh.clone());
        assert_eq!(cache.get("example.com"), Some(fresh));
    }

    #[test]
    fn get_absent_host_is_none() {
        let cache = DnsCache::new();
        assert_eq!(cache.get("never-inserted.example"), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn expired_entry_reads_as_absent_and_is_removed() {
        let cache = DnsCache::new();
        // ttl ZERO: expires the moment it is inserted.
        cache.insert(
            "old.example",
            answer(Duration::ZERO, stamp(now()), &["1.2.3.4"]),
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("old.example"), None);
        // Lazy removal on access: the read swept the dead entry.
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn fresh_entry_survives_alongside_an_expired_one() {
        let cache = DnsCache::new();
        cache.insert(
            "old.example",
            answer(Duration::ZERO, stamp(now()), &["1.2.3.4"]),
        );
        let fresh = answer(Duration::from_secs(3600), stamp(now()), &["5.6.7.8"]);
        cache.insert("new.example", fresh.clone());
        assert_eq!(cache.get("new.example"), Some(fresh));
        assert_eq!(cache.get("old.example"), None);
        // old was swept by its get; only the fresh one remains.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn is_fresh_saturates_instead_of_overflowing() {
        // A maximal TTL and an ancient-but-representable stamp must
        // saturate at i64::MAX, not panic and not wrap into "expired".
        let ancient = answer(Duration::MAX, stamp(-377_705_000_000), &["1.2.3.4"]);
        assert!(is_fresh(&ancient, now_unix()));
        let just_now = answer(Duration::ZERO, stamp(now_unix()), &["1.2.3.4"]);
        // now + 0 > now is false: expires immediately.
        assert!(!is_fresh(&just_now, now_unix()));
    }

    // -- format_line / parse_line ---------------------------------------------

    #[test]
    fn parse_line_accepts_minimal_valid_line() {
        let parsed = parse_line("host.example\t1.2.3.4\t60\t1700000000").unwrap();
        assert_eq!(parsed.0, "host.example");
        assert_eq!(parsed.1.addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(parsed.1.ttl, Duration::from_secs(60));
        assert_eq!(parsed.1.resolved_at.unix_timestamp(), 1_700_000_000);
    }

    #[test]
    fn parse_line_rejects_malformed_lines() {
        let bad = [
            // wrong field count
            "host.example\t1.2.3.4\t60",
            "",
            // empty host / empty addrs
            "\t1.2.3.4\t60\t1700000000",
            "host.example\t\t60\t1700000000",
            // bad ip, including one bad addr inside a list
            "host.example\tnot-an-ip\t60\t1700000000",
            "host.example\t1.2.3.4,zzz\t60\t1700000000",
            // bad ttl / bad timestamp
            "host.example\t1.2.3.4\tabc\t1700000000",
            "host.example\t1.2.3.4\t60\tabc",
            "host.example\t1.2.3.4\t60\t99999999999999999999",
            // extra field rides along in field 4 and breaks the stamp
            "host.example\t1.2.3.4\t60\t1700000000\textra",
            // from_unix_timestamp out of range
            "host.example\t1.2.3.4\t60\t999999999999999",
        ];
        for line in bad {
            assert_eq!(parse_line(line), None, "line {line:?} must be rejected");
        }
    }

    #[test]
    fn parse_line_accepts_negative_pre_1970_stamp() {
        let parsed = parse_line("host.example\t1.2.3.4\t60\t-1000").unwrap();
        assert_eq!(parsed.1.resolved_at.unix_timestamp(), -1000);
    }

    #[test]
    fn format_parse_round_trip_truncates_sub_second_stamps() {
        let original = OffsetDateTime::from_unix_timestamp(1_700_000_123)
            .unwrap()
            .replace_nanosecond(500_000_000)
            .unwrap();
        let answer = answer(Duration::from_secs(90), original, &["1.2.3.4", "::1"]);
        let line = format_line("host.example", &answer);
        let (host, parsed) = parse_line(&line).unwrap();
        assert_eq!(host, "host.example");
        assert_eq!(parsed.ttl, Duration::from_secs(90));
        assert_eq!(parsed.addrs, answer.addrs);
        // On-disk precision is whole seconds: the parsed stamp is the
        // truncated one, not the original.
        assert_eq!(parsed.resolved_at.unix_timestamp(), 1_700_000_123);
        assert_eq!(
            parsed.resolved_at.unix_timestamp(),
            original.unix_timestamp()
        );
    }

    // -- save / load ------------------------------------------------------------

    #[tokio::test]
    async fn save_load_round_trip_preserves_entries_exactly() {
        let dir = tmp_dir();
        let path = dir.join("dns-cache.txt");
        let cache = DnsCache::new();
        let base = now();
        let a = answer(Duration::from_secs(3600), stamp(base - 30), &["1.2.3.4"]);
        let b = answer(
            Duration::from_secs(3599),
            stamp(base - 20),
            &["5.6.7.8", "9.10.11.12"],
        );
        let c = answer(
            Duration::from_secs(3601),
            stamp(base - 10),
            &["2001:db8::1"],
        );
        cache.insert("a.example", a.clone());
        cache.insert("b.example", b.clone());
        cache.insert("c.example", c.clone());

        cache.save(&path).await.unwrap();
        let loaded = DnsCache::load(&path).await;
        assert_eq!(loaded.get("a.example"), Some(a));
        assert_eq!(loaded.get("b.example"), Some(b));
        assert_eq!(loaded.get("c.example"), Some(c));
        assert_eq!(loaded.len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn save_skips_expired_entries() {
        let dir = tmp_dir();
        let path = dir.join("dns-cache.txt");
        let cache = DnsCache::new();
        let base = now();
        cache.insert(
            "gone.example",
            answer(Duration::ZERO, stamp(base - 5000), &["1.2.3.4"]),
        );
        let kept = answer(Duration::from_secs(3600), stamp(base), &["5.6.7.8"]);
        cache.insert("kept.example", kept.clone());

        cache.save(&path).await.unwrap();
        let loaded = DnsCache::load(&path).await;
        assert_eq!(loaded.get("gone.example"), None);
        assert_eq!(loaded.get("kept.example"), Some(kept));
        assert_eq!(loaded.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_cache_saves_and_loads_as_empty() {
        let dir = tmp_dir();
        let path = dir.join("dns-cache.txt");
        let cache = DnsCache::new();
        cache.save(&path).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), Vec::<u8>::new());

        let loaded = DnsCache::load(&path).await;
        assert!(loaded.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn load_missing_file_is_empty_cache() {
        let dir = tmp_dir();
        let path = dir.join("does-not-exist.txt");
        let loaded = DnsCache::load(&path).await;
        assert!(loaded.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn load_corrupted_file_skips_garbage_keeps_valid_line() {
        let dir = tmp_dir();
        let path = dir.join("dns-cache.txt");
        let base = now();
        let valid = answer(Duration::from_secs(3600), stamp(base), &["1.2.3.4"]);
        let good_line = format_line("ok.example", &valid);
        std::fs::write(
            &path,
            format!("total garbage\n\n{good_line}\nnonsense\t×\t×\t×\n"),
        )
        .unwrap();

        let loaded = DnsCache::load(&path).await;
        assert_eq!(loaded.get("ok.example"), Some(valid));
        assert_eq!(loaded.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- cap and eviction ---------------------------------------------------

    #[test]
    fn cap_evicts_oldest_expiring_keeps_newest() {
        let cache = DnsCache::new();
        let base = now();
        for index in 0..DNS_CACHE_CAP + 5 {
            let host = format!("host-{index}");
            // Octet-safe unique address per index (4096+ fits in 3 octets).
            let addr = format!(
                "10.{}.{}.{}",
                (index >> 16) & 0xff,
                (index >> 8) & 0xff,
                index & 0xff
            );
            cache.insert(
                &host,
                answer(Duration::from_secs(3600), stamp(base), &[&addr]),
            );
        }
        assert_eq!(cache.len(), DNS_CACHE_CAP);
        let last = format!("host-{}", DNS_CACHE_CAP + 4);
        // New entries win: the newest host is still retrievable.
        assert!(cache.get(&last).is_some());
    }

    #[test]
    fn cap_pressure_sweeps_expired_before_evicting_fresh() {
        let cache = DnsCache::new();
        let base = now();
        // Fill to the cap with expired entries.
        for index in 0..DNS_CACHE_CAP {
            let host = format!("dead-{index}");
            let addr = format!("10.1.{}.{}", (index >> 8) & 0xff, index & 0xff);
            cache.insert(&host, answer(Duration::ZERO, stamp(base - 5000), &[&addr]));
        }
        // One fresh entry squeezed in under cap pressure must not evict a
        // fresh peer, and must itself survive.
        let fresh = answer(Duration::from_secs(3600), stamp(base), &["10.2.3.4"]);
        cache.insert("survivor.example", fresh.clone());
        assert!(cache.len() <= DNS_CACHE_CAP);
        assert_eq!(cache.get("survivor.example"), Some(fresh));
    }
}
