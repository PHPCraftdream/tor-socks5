//! Versioned packet persistence, not the obsolete host/address text rows.
//! v1: magic, repeated [stamp i128 nanos, ttl u64 secs, ttl u32 nanos,
//! packet length u32, DNS packet]. All integers are big endian.
//! Bad framed packets are skipped; a truncated frame stops parsing safely.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

const MAGIC: &[u8] = b"TOR-DNS-PACKETS\0\x01";
const FRAME_HEADER: usize = 32;
const MAX_FILE: usize = MAX_PAYLOAD + DNS_CACHE_CAP * FRAME_HEADER + MAGIC.len();
static SAVE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn save(path: &Path, entries: &[Entry]) -> io::Result<()> {
    // Standalone uniqueness counter, not a publication flag. Overflow is an
    // error rather than permitting temp-name reuse.
    let sequence = SAVE_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| io::Error::other("cache save sequence exhausted"))?;
    let mut temp = persist_lock::TempFileGuard::create(path, sequence)?;
    temp.write_all(MAGIC)?;
    for entry in entries {
        temp.write_all(&entry.resolved_at.unix_timestamp_nanos().to_be_bytes())?;
        temp.write_all(&entry.ttl.as_secs().to_be_bytes())?;
        temp.write_all(&entry.ttl.subsec_nanos().to_be_bytes())?;
        let length = u32::try_from(entry.packet.len())
            .map_err(|_| io::Error::other("cache packet exceeds length field"))?;
        temp.write_all(&length.to_be_bytes())?;
        temp.write_all(&entry.packet)?;
    }
    temp.fsync()?;
    temp.rename_into_target()
}

pub(super) fn load(path: &Path, now: OffsetDateTime, instant: Instant) -> Entries {
    persist_lock::cleanup_temp_files(path);
    let Ok(file) = File::open(path) else {
        return HashMap::new();
    };
    let mut data = Vec::new();
    // Cap the actual read, not only metadata (file can grow concurrently).
    if file
        .take(u64::try_from(MAX_FILE + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut data)
        .is_err()
        || data.len() > MAX_FILE
    {
        return HashMap::new();
    }
    decode(&data, now, instant)
}

fn take<const N: usize>(data: &mut &[u8]) -> Option<[u8; N]> {
    let result = data.get(..N)?.try_into().ok()?;
    *data = data.get(N..)?;
    Some(result)
}

pub(super) fn decode(data: &[u8], now: OffsetDateTime, instant: Instant) -> Entries {
    let mut entries = HashMap::new();
    if data.len() > MAX_FILE || !data.starts_with(MAGIC) {
        return entries;
    }
    let mut data = &data[MAGIC.len()..];
    // Bound frames processed too, including corrupt frames; valid entries are
    // separately bounded by admit. No obsolete address-row compatibility.
    for _ in 0..DNS_CACHE_CAP {
        let Some(stamp) = take::<16>(&mut data) else {
            break;
        };
        let Some(seconds) = take::<8>(&mut data) else {
            break;
        };
        let Some(nanos) = take::<4>(&mut data) else {
            break;
        };
        let Some(length) = take::<4>(&mut data) else {
            break;
        };
        let Ok(length) = usize::try_from(u32::from_be_bytes(length)) else {
            break;
        };
        let Some(packet) = data.get(..length) else {
            break;
        };
        data = &data[length..];
        if length > MAX_PACKET {
            continue;
        }
        let Ok(resolved_at) = OffsetDateTime::from_unix_timestamp_nanos(i128::from_be_bytes(stamp))
        else {
            continue;
        };
        let nanos = u32::from_be_bytes(nanos);
        if nanos >= 1_000_000_000 {
            continue;
        }
        let ttl = Duration::new(u64::from_be_bytes(seconds), nanos);
        let Some(initial_age) = wall_age(resolved_at, now) else {
            continue;
        };
        let Ok(message) = Message::from_vec(packet) else {
            continue;
        };
        let Some(query) = message.queries.first() else {
            continue;
        };
        let Some(policy_ttl) = cache_ttl(query, &message) else {
            continue;
        };
        let ttl = ttl.min(policy_ttl);
        if ttl <= initial_age {
            continue;
        }
        let entry = Entry {
            packet: Arc::from(packet),
            ttl,
            resolved_at,
            admitted: instant,
            initial_age,
        };
        admit(&mut entries, admitted_query(query), entry, now, instant);
    }
    entries
}

#[cfg(test)]
pub(super) fn encode_fixture(entries: &[Entry]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    for entry in entries {
        bytes.extend(entry.resolved_at.unix_timestamp_nanos().to_be_bytes());
        bytes.extend(entry.ttl.as_secs().to_be_bytes());
        bytes.extend(entry.ttl.subsec_nanos().to_be_bytes());
        bytes.extend(u32::try_from(entry.packet.len()).unwrap().to_be_bytes());
        bytes.extend(entry.packet.iter());
    }
    bytes
}
