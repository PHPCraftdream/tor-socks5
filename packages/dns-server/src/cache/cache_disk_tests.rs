use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        // create_dir (not create_dir_all) never reuses/deletes another test's dir.
        loop {
            let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("dns-packet-tests-{}-{seq}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("scratch directory: {error}"),
            }
        }
    }
    fn file(&self) -> PathBuf {
        self.0.join("cache.bin")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn snapshot(cache: &DnsCache) -> Vec<Entry> {
    lock_entries(&cache.entries).values().cloned().collect()
}

#[test]
fn disk_roundtrip_preserves_packets_nanos_type_class_case_and_expiry() {
    let scratch = Scratch::new();
    let cache = DnsCache::new();
    let instant = Instant::now();
    let mut original = answer(&q(), 90);
    original.resolved_at = epoch().replace_nanosecond(123_456_789).unwrap();
    let now = original.resolved_at;
    cache.insert_at(&q(), &original, now, instant);
    let other = query("WWW.EXAMPLE.", RecordType::A, DNSClass::CH);
    cache.insert_at(&other, &answer(&other, 60), now, instant);
    disk::save(&scratch.file(), &snapshot(&cache)).unwrap();
    let loaded = DnsCache::from_entries(disk::load(&scratch.file(), now, instant));
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.get_at(&q(), now, instant).unwrap(), original);
    assert!(loaded.get_at(&other, now, instant).is_some());
    assert!(loaded
        .get_at(
            &query("www.example.", RecordType::AAAA, DNSClass::IN),
            now,
            instant
        )
        .is_none());
    let end = now + time::Duration::seconds(90);
    assert!(DnsCache::from_entries(disk::load(&scratch.file(), end, instant)).is_empty());
}

#[test]
fn disk_restore_relative_admission_accepts_relative_and_absolute_case_variants() {
    let scratch = Scratch::new();
    let relative = query("WWW.Example", RecordType::A, DNSClass::IN);
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&relative, &answer(&q(), 60), epoch(), instant);
    disk::save(&scratch.file(), &snapshot(&cache)).unwrap();
    let loaded = DnsCache::from_entries(disk::load(&scratch.file(), epoch(), instant));
    assert_eq!(loaded.len(), 1);
    assert!(loaded.get_at(&relative, epoch(), instant).is_some());
    assert!(loaded.get_at(&q(), epoch(), instant).is_some());
    let end = epoch() + time::Duration::seconds(60);
    assert!(loaded.get_at(&relative, end, instant).is_none());
    assert!(loaded.is_empty());
}

#[test]
fn disk_save_load_save_never_restamps_or_rejuvenates() {
    let scratch = Scratch::new();
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&q(), &answer(&q(), 60), epoch(), instant);
    disk::save(&scratch.file(), &snapshot(&cache)).unwrap();
    let later = epoch() + time::Duration::seconds(40);
    let loaded = DnsCache::from_entries(disk::load(&scratch.file(), later, instant));
    assert_eq!(
        loaded.get_at(&q(), later, instant).unwrap().ttl,
        Duration::from_secs(20)
    );
    disk::save(&scratch.file(), &snapshot(&loaded)).unwrap();
    let end = epoch() + time::Duration::seconds(60);
    assert!(disk::load(&scratch.file(), end, instant).is_empty());
}

#[test]
fn disk_negative_roundtrip_retains_soa_rcode_and_decrements_negative_ttl() {
    let scratch = Scratch::new();
    let instant = Instant::now();
    for rcode in [ResponseCode::NoError, ResponseCode::NXDomain] {
        let cache = DnsCache::new();
        cache.insert_at(&q(), &negative(&q(), rcode, 120, 45), epoch(), instant);
        disk::save(&scratch.file(), &snapshot(&cache)).unwrap();
        let later = epoch() + time::Duration::seconds(10);
        let loaded = DnsCache::from_entries(disk::load(&scratch.file(), later, instant));
        let hit = loaded.get_at(&q(), later, instant).unwrap();
        assert_eq!(hit.message.metadata.response_code, rcode);
        assert_eq!(hit.message.authorities[0].ttl, 35);
        assert_eq!(hit.ttl, Duration::from_secs(35));
    }
}

#[test]
fn disk_corruption_old_rows_versions_and_noncacheable_packets_fail_closed() {
    let instant = Instant::now();
    let cache = DnsCache::new();
    cache.insert_at(&q(), &answer(&q(), 60), epoch(), instant);
    let good = disk::encode_fixture(&snapshot(&cache));
    for length in 0..good.len() {
        assert!(disk::decode(&good[..length], epoch(), instant).is_empty());
    }
    assert!(disk::decode(b"www.example\t1.2.3.4\t60\t1700000000\n", epoch(), instant).is_empty());
    let mut wrong_version = good.clone();
    wrong_version[16] = 2;
    assert!(disk::decode(&wrong_version, epoch(), instant).is_empty());
    let mut invalid_frame = snapshot(&cache)[0].clone();
    invalid_frame.packet = Arc::from([0_u8; 12]);
    let mut frames = vec![invalid_frame];
    frames.extend(snapshot(&cache));
    assert_eq!(
        disk::decode(&disk::encode_fixture(&frames), epoch(), instant).len(),
        1
    );
    let mut failure = answer(&q(), 60);
    failure.message.metadata.response_code = ResponseCode::ServFail;
    frames[0].packet = failure.message.to_vec().unwrap().into();
    assert_eq!(
        disk::decode(&disk::encode_fixture(&frames), epoch(), instant).len(),
        1
    );
}

#[test]
fn disk_cap_and_payload_budget_bound_restored_state() {
    let instant = Instant::now();
    let cache = DnsCache::new();
    cache.insert_at(&q(), &answer(&q(), 600), epoch(), instant);
    let template = snapshot(&cache)[0].clone();
    let mut frames = Vec::new();
    for index in 0..DNS_CACHE_CAP + 1 {
        let query = query(
            &format!("host-{index}.example."),
            RecordType::A,
            DNSClass::IN,
        );
        let mut entry = template.clone();
        entry.packet = answer(&query, 600).message.to_vec().unwrap().into();
        frames.push(entry);
    }
    let restored = disk::decode(&disk::encode_fixture(&frames), epoch(), instant);
    assert_eq!(restored.len(), DNS_CACHE_CAP);
    // Exercise aggregate admission directly with maximally sized retained packets.
    let mut entries = HashMap::new();
    for index in 0..300 {
        let query = query(
            &format!("large-{index}.example."),
            RecordType::A,
            DNSClass::IN,
        );
        let mut entry = template.clone();
        entry.packet = vec![0; MAX_PACKET].into();
        admit(
            &mut entries,
            admitted_query(&query),
            entry,
            epoch(),
            instant,
        );
    }
    assert!(
        entries
            .values()
            .map(|entry| entry.packet.len())
            .sum::<usize>()
            <= MAX_PAYLOAD
    );
    assert!(entries.len() < 300);
    assert!(disk::decode(
        &vec![0; MAX_PAYLOAD + DNS_CACHE_CAP * 32 + 17],
        epoch(),
        instant
    )
    .is_empty());
}

#[tokio::test]
async fn cancelled_save_retains_serialization_until_worker_finishes() {
    let scratch = Scratch::new();
    let cache = Arc::new(DnsCache::new());
    let now = OffsetDateTime::now_utc();
    let mut original = answer(&q(), 600);
    original.resolved_at = now;
    cache.insert(&q(), &original);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    *cache.save_seam.lock().unwrap() = Some(SaveSeam {
        entered: entered_tx,
        release: release_rx,
    });
    let first_cache = cache.clone();
    let first_path = scratch.file();
    let first = tokio::spawn(async move { first_cache.save(&first_path).await });
    entered_rx.await.unwrap();
    first.abort();
    let cancelled = first.await.unwrap_err().is_cancelled();
    let worker_holds_gate = cache.save_lock.try_lock().is_err();
    let mut replacement = answer(&q(), 600);
    replacement.resolved_at = OffsetDateTime::now_utc();
    replacement.message.answers[0].data = RData::A(A::new(9, 8, 7, 6));
    cache.insert(&q(), &replacement);
    release_tx.send(()).unwrap();
    assert!(cancelled);
    assert!(
        worker_holds_gate,
        "cancelled caller must not release worker's gate"
    );
    cache.save(&scratch.file()).await.unwrap();
    let loaded = DnsCache::load(&scratch.file()).await;
    assert_eq!(
        loaded.get(&q()).unwrap().message.answers[0].data,
        RData::A(A::new(9, 8, 7, 6))
    );
}
