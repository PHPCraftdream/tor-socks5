//! Unit tests for the temp-file ownership protocol in [`super`]: name
//! builder/recogniser pairing, guard publish/rollback, the companion lock
//! discipline, and the TS18-01 forcing tests for the two interleaving
//! windows.

use super::seam;
use super::*;

/// Forcing tests park real library threads on the seam slots; serialize
/// them so concurrent unit tests cannot cross-talk on a slot.
static FORCING: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tmp_dir() -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-persist-lock-test-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn temp_name_round_trips_through_parse() {
    for target in ["store.log", "tor-socks5.ktav", "data", "a.b.c"] {
        for (pid, seq) in [(1u32, 0u64), (4_294_967_295, 18_446_744_073_709_551_615)] {
            let name = temp_file_name(target, pid, seq);
            assert_eq!(parse_temp_name(&name, target), Some((pid, seq)));
        }
    }
}

#[test]
fn parse_rejects_malformed_names() {
    let negatives = [
        ".t.xyz.1.tmp",         // garbage pid
        ".t.99999999999.1.tmp", // pid > u32::MAX
        ".t.1.abc.tmp",         // non-numeric seq
        ".t.1.tmp",             // missing seq
        ".t.1.2.3.tmp",         // extra segment
        ".t.1.2.tmpx",          // wrong extension
        ".t.1.2.tmp.bak",       // extra segment after extension
        ".t.1.2.tmp.lock",      // the companion, not a temp
        ".other.1.2.tmp",       // different target prefix
        "t.1.2.tmp",            // no leading dot
    ];
    for name in negatives {
        assert_eq!(parse_temp_name(name, "t"), None, "{name}");
    }
}

#[test]
fn guard_finish_publishes_and_leaves_no_temp() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let mut guard = TempFileGuard::create(&target, 1).unwrap();
    let temp = guard.temp_path().to_path_buf();
    assert!(temp.exists());
    assert!(parse_temp_name(temp.file_name().unwrap().to_str().unwrap(), "store.log").is_some());
    guard.write_all(b"hello").unwrap();
    guard.finish().unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"hello");
    assert!(!temp.exists());
    assert_eq!(
        fs::read_dir(&dir).unwrap().count(),
        2,
        "no temp and no companion left; the two entries are the published \
         target and the permanent <target>.templock"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The published file must be readable the instant `finish` returns. A
/// lock held on the temp itself stayed in force on the target for the
/// moments between the rename and the handle's close, and on Windows —
/// where `File::lock` is mandatory — every reader in that window failed
/// with os error 33. The lock lives on a companion precisely so this
/// cannot happen.
#[test]
fn published_target_is_immediately_readable() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    for seq in 0..50 {
        let mut guard = TempFileGuard::create(&target, seq).unwrap();
        guard.write_all(b"published").unwrap();
        guard.finish().unwrap();
        assert_eq!(
            fs::read(&target).expect("published target reads without a lock conflict"),
            b"published"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Readers must also be able to read the PREVIOUS contents of the target
/// while a writer is mid-save, which is the normal steady state.
#[test]
fn target_stays_readable_while_a_guard_is_open() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    fs::write(&target, b"old").unwrap();
    let mut guard = TempFileGuard::create(&target, 7).unwrap();
    guard.write_all(b"new").unwrap();
    assert_eq!(
        fs::read(&target).expect("target reads while a save is in flight"),
        b"old"
    );
    guard.finish().unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn guard_drop_without_finish_removes_temp_and_keeps_target() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    fs::write(&target, b"keep").unwrap();
    let temp;
    {
        let mut guard = TempFileGuard::create(&target, 2).unwrap();
        temp = guard.temp_path().to_path_buf();
        guard.write_all(b"partial").unwrap();
    }
    assert!(!temp.exists());
    assert!(!lock_path_for(&temp).exists(), "companion removed too");
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unlocked_file_is_removed_locked_file_survives() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let plain = dir.join(".store.log.1.9.tmp");
    fs::write(&plain, b"dead owner").unwrap();
    assert!(remove_temp_if_unlocked(&target, &plain));
    assert!(!plain.exists());

    let guard = TempFileGuard::create(&target, 3).unwrap();
    assert!(!remove_temp_if_unlocked(&target, guard.temp_path()));
    assert!(guard.temp_path().exists());
    drop(guard);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cleanup_skips_live_temp_and_removes_dead_one() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let guard = TempFileGuard::create(&target, 4).unwrap();
    let dead = dir.join(temp_file_name("store.log", 12345, 77));
    fs::write(&dead, b"dead").unwrap();

    cleanup_temp_files(&target);

    assert!(guard.temp_path().exists(), "live writer's temp survives");
    assert!(
        lock_path_for(guard.temp_path()).exists(),
        "live writer's companion survives"
    );
    assert!(!dead.exists(), "ownerless temp is cleaned");
    drop(guard);
    let _ = fs::remove_dir_all(&dir);
}

/// A dead writer that got as far as the rename leaves its companion
/// behind with no temp next to it. Nothing else would ever remove it, so
/// cleanup has to — but only when its lock can be acquired.
#[test]
fn cleanup_removes_an_orphan_companion_but_spares_a_live_one() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let orphan = lock_path_for(&dir.join(temp_file_name("store.log", 4242, 5)));
    fs::write(&orphan, b"").unwrap();

    let guard = TempFileGuard::create(&target, 6).unwrap();
    let live_lock = lock_path_for(guard.temp_path());

    cleanup_temp_files(&target);

    assert!(!orphan.exists(), "orphan companion is cleaned");
    assert!(live_lock.exists(), "live writer's companion survives");
    assert!(guard.temp_path().exists(), "live writer's temp survives");
    drop(guard);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cleanup_with_legacy_removes_legacy_and_malformed_survives_both() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let legacy = dir.join(".store.log.tmp.old");
    fs::write(&legacy, b"legacy").unwrap();
    let malformed = dir.join(".store.log.not-a-pid.1.tmp");
    fs::write(&malformed, b"garbage").unwrap();

    cleanup_temp_files_with(&target, |n| n == ".store.log.tmp.old");
    assert!(!legacy.exists(), "legacy temp cleaned");
    assert!(malformed.exists(), "malformed name survives first cleanup");

    cleanup_temp_files(&target);
    assert!(malformed.exists(), "malformed name survives second cleanup");
    let _ = fs::remove_dir_all(&dir);
}

/// The templock is part of the protocol's permanent furniture: cleanup
/// never removes it, and publishing leaves it in place.
#[test]
fn templock_is_permanent_across_cleanup_and_publish() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let templock = templock_path_for(&target);
    let guard = TempFileGuard::create(&target, 8).unwrap();
    assert!(templock.exists(), "create establishes the templock");
    cleanup_temp_files(&target);
    assert!(templock.exists(), "cleanup never unlinks the templock");
    guard.finish().unwrap();
    assert!(templock.exists(), "publish leaves the templock in place");
    let _ = fs::remove_dir_all(&dir);
}

/// Cleanup must never nominate the `*.templock` file, not even through an
/// aggressively-nominating legacy predicate.
#[test]
fn cleanup_never_nominates_the_templock_file() {
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let templock = templock_path_for(&target);
    fs::write(&templock, b"section lock").unwrap();

    cleanup_temp_files_with(&target, |_| true);

    assert!(templock.exists(), "the templock file survives cleanup");
    let _ = fs::remove_dir_all(&dir);
}

/// TS18-01 forcing test, window 1: cleanup must not be able to take the
/// companion lock and unlink the companion name while a writer is parked
/// inside `create` between opening the companion and its `try_lock`, and
/// the writer's save must survive the NEXT cleanup and publish.
///
/// Counterfactual scope, measured rather than assumed: removing the
/// critical section from `create` and from both cleanup paths does NOT
/// turn this test red on Windows. `remove_file` on a name whose handle is
/// still open is a *pending delete* there -- the name stays visible until
/// the last handle closes, and the next `open` of it fails with
/// ACCESS_DENIED rather than NotFound, so cleanup's delete-on-missing-
/// companion branch is never reached. The interleaving this test drives is
/// therefore only harmful where unlink takes effect immediately, i.e. on
/// Unix. What pins the protocol on this platform is
/// `cleanup_window_in_remove_temp_if_unlocked_cannot_kill_a_new_writer`
/// (verified red without the section) plus
/// `templock_is_permanent_across_cleanup_and_publish`. Keep this test for
/// the Unix side of the contract, but do not read a green run here as
/// evidence on Windows.
#[test]
fn cleanup_cannot_steal_companion_of_writer_between_open_and_try_lock() {
    let _serial = FORCING.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tmp_dir();
    let target = dir.join("store.log");

    seam::arm(seam::CREATE_BEFORE_OWNERSHIP);
    let writer = {
        let target = target.clone();
        std::thread::spawn(move || {
            seam::enable();
            TempFileGuard::create(&target, 1)
        })
    };
    assert!(
        seam::wait_parked(seam::CREATE_BEFORE_OWNERSHIP),
        "writer never parked in create — seam broken"
    );

    // A full cleanup sweep runs while the writer is parked. (On the
    // pre-fix protocol it observes a companion without a temp, acquires
    // the free lock, and unlinks the name out from under the parked
    // writer's open handle.)
    cleanup_temp_files(&target);

    seam::release(seam::CREATE_BEFORE_OWNERSHIP);
    let mut guard = writer.join().unwrap().expect("create must succeed");
    let temp = guard.temp_path().to_path_buf();
    assert!(temp.exists(), "writer's temp must exist after create");

    guard.write_all(b"ts18-01-w1").unwrap();

    // The next cleanup must still recognise the live owner's companion.
    cleanup_temp_files(&target);
    assert!(
        temp.exists(),
        "TS18-01: live writer's temp deleted by a later cleanup"
    );

    guard.finish().expect("TS18-01: publish must succeed");
    assert_eq!(fs::read(&target).unwrap(), b"ts18-01-w1");

    seam::disarm(seam::CREATE_BEFORE_OWNERSHIP);
    let _ = fs::remove_dir_all(&dir);
}

/// TS18-01 forcing test, window 2: a remover parked between `drop(lock)`
/// and `remove_file(lock_path)` — after having decided "ownerless" — and
/// a creator that already opened that same companion. Whoever wins the
/// window, the creator's save must still be alive and publishable.
#[test]
fn cleanup_window_in_remove_temp_if_unlocked_cannot_kill_a_new_writer() {
    let _serial = FORCING.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tmp_dir();
    let target = dir.join("store.log");
    let seq = 11u64;
    let temp = dir.join(temp_file_name("store.log", std::process::id(), seq));
    let companion = lock_path_for(&temp);
    // A dead writer's leftovers: an unlocked companion and a temp.
    fs::write(&temp, b"dead").unwrap();
    fs::write(&companion, b"").unwrap();

    seam::arm(seam::CREATE_BEFORE_OWNERSHIP);
    seam::arm(seam::UNLOCKED_BEFORE_UNLINK);
    // The remover enters FIRST: it acquires the state-transition lock
    // (in the fixed protocol) and parks inside the unlink window. In the
    // fixed world this blocks any creator behind the same lock until it
    // is released, so the choreography below stays deterministic.
    let remover = {
        let target = target.clone();
        let temp = temp.clone();
        std::thread::spawn(move || {
            seam::enable();
            remove_temp_if_unlocked(&target, &temp)
        })
    };
    assert!(
        seam::wait_parked(seam::UNLOCKED_BEFORE_UNLINK),
        "remover never reached the unlink window — seam broken"
    );

    // Only now does the creator run. On the buggy protocol it opens the
    // leftover companion and parks before its try_lock; on the fixed
    // protocol it is blocked on the state-transition lock the parked
    // remover holds and never reaches the seam.
    let creator = {
        let target = target.clone();
        std::thread::spawn(move || {
            seam::enable();
            TempFileGuard::create(&target, seq)
        })
    };
    let creator_parked = seam::wait_parked(seam::CREATE_BEFORE_OWNERSHIP);

    if creator_parked {
        // BUGGY protocol (TS18-01 counterfactual): the remover deletes
        // the leftover temp while the creator holds an open handle to the
        // now-unlinked companion inode and recreates the temp name. The
        // later cleanup sees companion-NotFound and deletes the creator's
        // LIVE temp; the assertions below MUST fail.
        seam::release(seam::UNLOCKED_BEFORE_UNLINK);
        seam::release(seam::CREATE_BEFORE_OWNERSHIP);
        let mut guard = creator.join().unwrap().expect("creator must succeed");
        assert!(
            remover.join().unwrap(),
            "remover must report the leftover removed"
        );
        assert!(
            guard.temp_path().exists(),
            "TS18-01: creator's temp deleted out from under it"
        );

        guard.write_all(b"ts18-01-w2").unwrap();
        cleanup_temp_files(&target);
        assert!(
            guard.temp_path().exists(),
            "TS18-01: creator's temp deleted by a later cleanup"
        );

        guard.finish().expect("TS18-01: publish must succeed");
        assert_eq!(fs::read(&target).unwrap(), b"ts18-01-w2");
    } else {
        // FIXED protocol: the remover legitimately removes the ownerless
        // leftovers and releases the lock; the creator then creates fresh
        // companion + temp inside the critical section. It never parked,
        // so also issue a sticky release(CREATE) — a harmless no-op.
        seam::release(seam::UNLOCKED_BEFORE_UNLINK);
        seam::release(seam::CREATE_BEFORE_OWNERSHIP);
        let mut guard = creator.join().unwrap().expect("creator must succeed");
        assert!(
            remover.join().unwrap(),
            "remover must report the leftover removed"
        );

        guard.write_all(b"ts18-01-w2").unwrap();
        // The next cleanup must spare the live writer's temp: its
        // companion exists and is locked.
        cleanup_temp_files(&target);
        assert!(
            guard.temp_path().exists(),
            "TS18-01: creator's temp deleted by a later cleanup"
        );

        guard.finish().expect("TS18-01: publish must succeed");
        assert_eq!(fs::read(&target).unwrap(), b"ts18-01-w2");
    }

    seam::disarm(seam::CREATE_BEFORE_OWNERSHIP);
    seam::disarm(seam::UNLOCKED_BEFORE_UNLINK);
    let _ = fs::remove_dir_all(&dir);
}
