//! Bounded, packet-aware DNS cache. Lock order: save gate, then entries.
//! Packet bytes and original timestamps are immutable; reads age a decoded copy.
//! Persistence never writes an aged copy or restamps the original resolution.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use time::OffsetDateTime;

use crate::error::DnsServerError;
use crate::types::{cache_ttl, normalize_negative_soa_ttl, ResolvedAnswer};

#[path = "cache_disk.rs"]
mod disk;
#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;

/// Maximum number of cached query tuples.
pub const DNS_CACHE_CAP: usize = 4096;
const MAX_PACKET: usize = 65_535;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

type Entries = HashMap<Query, Entry>;

fn admitted_query(query: &Query) -> Query {
    let mut key = query.clone();
    key.name.set_fqdn(true);
    key
}

fn same_question(left: &Query, right: &Query) -> bool {
    left.name().eq_ignore_root(right.name())
        && left.query_type() == right.query_type()
        && left.query_class() == right.query_class()
}

#[derive(Clone)]
struct Entry {
    packet: Arc<[u8]>,
    ttl: Duration,
    resolved_at: OffsetDateTime,
    admitted: Instant,
    initial_age: Duration,
}

impl Entry {
    fn age(&self, now: OffsetDateTime, instant: Instant) -> Duration {
        self.initial_age
            .saturating_add(instant.saturating_duration_since(self.admitted))
            .max(wall_age(self.resolved_at, now).unwrap_or_default())
    }

    fn remaining(&self, now: OffsetDateTime, instant: Instant) -> Duration {
        self.ttl.saturating_sub(self.age(now, instant))
    }
}

fn record_ttls(message: &Message) -> impl Iterator<Item = u32> + '_ {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .map(|record| record.ttl)
}

fn wall_age(stamp: OffsetDateTime, now: OffsetDateTime) -> Option<Duration> {
    Duration::try_from(now - stamp).ok()
}

/// Test-only handshake that parks a save worker while it owns its permit.
#[cfg(test)]
struct SaveSeam {
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

/// Thread-safe cache keyed by case-insensitive DNS name, type and class.
/// Evicts soonest-expiring entries under count or aggregate packet-byte pressure.
/// Saves are serialized per instance, including after cancellation of the caller.
/// DEVIATION from RFC 2308 §5: NXDOMAIN is kept per type as required by the
/// shared packet-cache contract, rather than reused across all query types.
pub struct DnsCache {
    entries: Arc<Mutex<Entries>>,
    save_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(test)]
    save_seam: Arc<Mutex<Option<SaveSeam>>>,
}

impl DnsCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self::from_entries(HashMap::new())
    }

    fn from_entries(entries: Entries) -> Self {
        Self {
            entries: Arc::new(Mutex::new(entries)),
            save_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            save_seam: Arc::new(Mutex::new(None)),
        }
    }

    /// Return a fresh packet copy with aged ordinary RR TTLs (never OPT).
    /// `ttl` is the remaining lifetime; `resolved_at` is this copy's age epoch.
    /// Transport owners must replace transaction ID/question and adapt EDNS.
    pub fn get(&self, query: &Query) -> Option<ResolvedAnswer> {
        self.get_at(query, OffsetDateTime::now_utc(), Instant::now())
    }

    fn get_at(
        &self,
        query: &Query,
        now: OffsetDateTime,
        instant: Instant,
    ) -> Option<ResolvedAnswer> {
        let entry = {
            let mut entries = lock_entries(&self.entries);
            // Hickory hashes the FQDN flag. Absolute wire queries use borrowed
            // O(1) lookup; relative public queries use a bounded allocation-free
            // scan because Borrow<Query> cannot change that hash/equality.
            let entry = if query.name().is_fqdn() {
                entries.get_mut(query)?
            } else {
                entries
                    .iter_mut()
                    .find(|(key, _)| same_question(key, query))?
                    .1
            };
            if entry.remaining(now, instant).is_zero() {
                if query.name().is_fqdn() {
                    entries.remove(query);
                } else {
                    entries.retain(|key, _| !same_question(key, query));
                }
                return None;
            }
            // Retain the greatest observed age even if wall time jumps back.
            entry.initial_age = entry.age(now, instant);
            entry.admitted = instant;
            entry.clone()
        };
        let age = entry.age(now, instant);
        let mut message = Message::from_vec(&entry.packet).ok()?;
        let seconds = u32::try_from(age.as_secs()).unwrap_or(u32::MAX);
        normalize_negative_soa_ttl(query, &mut message);
        for record in message
            .answers
            .iter_mut()
            .chain(&mut message.authorities)
            .chain(&mut message.additionals)
        {
            if record.record_type() != RecordType::OPT {
                record.decrement_ttl(seconds);
            }
        }
        Some(ResolvedAnswer {
            message,
            ttl: entry.ttl.saturating_sub(age),
            resolved_at: now,
        })
    }

    /// Admit only useful NOERROR or SOA-backed NXDOMAIN/NODATA packets.
    /// Caller TTL can shorten, but cannot extend, the packet's DNS lifetime.
    pub fn insert(&self, query: &Query, answer: &ResolvedAnswer) {
        self.insert_at(query, answer, OffsetDateTime::now_utc(), Instant::now());
    }

    fn insert_at(
        &self,
        query: &Query,
        answer: &ResolvedAnswer,
        now: OffsetDateTime,
        instant: Instant,
    ) {
        let Some(policy_ttl) = cache_ttl(query, &answer.message) else {
            return;
        };
        let ttl = answer.ttl.min(policy_ttl);
        let Some(initial_age) = wall_age(answer.resolved_at, now) else {
            return;
        };
        if ttl <= initial_age {
            return;
        }
        let Ok(packet) = answer.message.to_vec() else {
            return;
        };
        if packet.len() > MAX_PACKET {
            return;
        }
        // Encoding must not silently truncate the packet at the encoder limit.
        let Ok(decoded) = Message::from_vec(&packet) else {
            return;
        };
        // Message has no stored header counts. Its derived equality does,
        // however, delegate to Record equality, which intentionally ignores
        // TTL (RFC 2136). Verify TTLs separately as part of packet fidelity.
        if decoded != answer.message || !record_ttls(&decoded).eq(record_ttls(&answer.message)) {
            return;
        }
        let entry = Entry {
            packet: packet.into(),
            ttl,
            resolved_at: answer.resolved_at,
            admitted: instant,
            initial_age,
        };
        admit(
            &mut lock_entries(&self.entries),
            admitted_query(query),
            entry,
            now,
            instant,
        );
    }

    /// Number of remembered tuples, including not-yet-swept expired entries.
    pub fn len(&self) -> usize {
        lock_entries(&self.entries).len()
    }

    /// Whether no query tuples are remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Best-effort bounded disk read and validation on the blocking pool.
    pub async fn load(path: &Path) -> Self {
        let path = path.to_owned();
        Self::from_entries(
            tokio::task::spawn_blocking(move || {
                disk::load(&path, OffsetDateTime::now_utc(), Instant::now())
            })
            .await
            .unwrap_or_default(),
        )
    }

    /// Atomically save original packets/stamps on the blocking pool.
    /// cancel-safe: publication already scheduled continues if the caller drops
    /// this future. The worker owns the save permit until rename completes, so
    /// cancellation cannot let an older snapshot overwrite a newer save.
    pub async fn save(&self, path: &Path) -> Result<(), DnsServerError> {
        let permit = self.save_lock.clone().lock_owned().await;
        let entries = self.entries.clone();
        #[cfg(test)]
        let seam = self.save_seam.clone();
        let path = path.to_owned();
        // If the join is cancelled, intentional detach: worker owns all resources
        // and serialization; no subsequent save can overtake its publication.
        let job = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            {
                let hook = seam.lock().unwrap().take();
                if let Some(SaveSeam { entered, release }) = hook {
                    let _ = entered.send(());
                    release.recv().unwrap();
                }
            }
            let now = OffsetDateTime::now_utc();
            let instant = Instant::now();
            let snapshot = {
                let mut entries = lock_entries(&entries);
                entries.retain(|_, entry| !entry.remaining(now, instant).is_zero());
                entries
                    .values()
                    .map(|entry| {
                        let mut snapshot = entry.clone();
                        // If wall time moved backward, persist the monotonic loss
                        // as a shorter lease, keeping the original packet/stamp.
                        let wall = wall_age(entry.resolved_at, now).unwrap_or_default();
                        snapshot.ttl = entry
                            .ttl
                            .min(entry.remaining(now, instant).saturating_add(wall));
                        snapshot
                    })
                    .collect::<Vec<_>>()
            };
            disk::save(&path, &snapshot)
        });
        let result = job.await.map_err(|error| DnsServerError::CacheIo {
            op: "save",
            source: std::io::Error::other(error.to_string()),
        })?;
        result.map_err(|source| DnsServerError::CacheIo { op: "save", source })
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_entries(entries: &Mutex<Entries>) -> MutexGuard<'_, Entries> {
    // Preserve valid entries after an unrelated panic. The map and its owned
    // immutable packets remain memory-safe; expiry/admission enforce their
    // normal bounds on subsequent access. Poison remains diagnostic state.
    entries.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn admit(entries: &mut Entries, key: Query, entry: Entry, now: OffsetDateTime, instant: Instant) {
    entries.retain(|_, existing| !existing.remaining(now, instant).is_zero());
    entries.remove(&key);
    let mut bytes: usize = entries.values().map(|value| value.packet.len()).sum();
    while entries.len() >= DNS_CACHE_CAP || bytes + entry.packet.len() > MAX_PAYLOAD {
        let victim = entries
            .iter()
            .min_by_key(|(_, value)| value.remaining(now, instant))
            .map(|(key, _)| key.clone());
        let Some(victim) = victim else { break };
        if let Some(removed) = entries.remove(&victim) {
            bytes -= removed.packet.len();
        }
    }
    entries.insert(key, entry);
}
