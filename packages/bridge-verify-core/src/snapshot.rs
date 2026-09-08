//! Builds a check-client cache dir as a consistent SQLite snapshot.
//!
//! Ported verbatim from the two byte-identical copies that used to live in
//! `apps/socks5-proxy/src/bridge_verifier.rs` and
//! `packages/android-ffi/src/jni_verify.rs` (they differed only in log-macro
//! spelling, log prefix, and `Path` import style). The log prefix is a
//! parameter so each consumer keeps its exact historical prefix string.

/// Builds `dest` as a usable check-client cache dir: either a CONSISTENT
/// snapshot of the live cache's SQLite database — taken with sqlite's Online
/// Backup API, which is safe against concurrent writers — plus a best-effort
/// copy of the rest of the source dir (`dir_blobs/**` and any unknown files),
/// or, when nothing consistent can be produced, an explicitly clean EMPTY
/// cache dir the check client cold-starts in. Returns `true` when `dest` is
/// usable. Never copies the live `dir.sqlite3` file directly (a plain file
/// copy of a hot database can interleave with the main engine's writes and
/// its journal/WAL sidecars, producing a torn copy), and never falls back to
/// sharing the live directory.
///
/// `log_prefix` prefixes every warning line (including its trailing space) so
/// each consumer keeps its exact historical log output, e.g.
/// `"circuit-verify: "` (CLI) or `"bridge-verify: "` (Android).
pub fn snapshot_cache_dir(
    src: &std::path::Path,
    dest: &std::path::Path,
    log_prefix: &'static str,
) -> bool {
    // ~4 MiB per step at the default 4 KiB page size: few steps for a
    // tor-dirmgr-sized DB, without hogging the writer between steps.
    const SNAPSHOT_BACKUP_PAGES_PER_STEP: i32 = 1024;
    // Bounded total budget. `Backup::run_to_completion` is deliberately NOT
    // used: it retries Busy forever.
    const SNAPSHOT_BACKUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

    const DB_NAME: &str = "dir.sqlite3";
    // Sidecars must never travel with a backup-API snapshot: a stale journal
    // or WAL next to the fresh DB would be actively harmful.
    const SIDECAR_NAMES: [&str; 3] = ["dir.sqlite3-journal", "dir.sqlite3-wal", "dir.sqlite3-shm"];
    // Per-process lock state; the check client makes its own.
    const REST_COPY_SKIP: [&str; 5] = [
        DB_NAME,
        "dir.sqlite3-journal",
        "dir.sqlite3-wal",
        "dir.sqlite3-shm",
        "dir.lock",
    ];

    fn remove_db_and_sidecars(dest: &std::path::Path) -> bool {
        // A missing sidecar is success (nothing to remove), not failure --
        // the backup API rarely leaves WAL/journal sidecars behind, so this
        // is the common case, not an edge case.
        fn remove_if_exists(path: &std::path::Path) -> bool {
            match std::fs::remove_file(path) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            }
        }
        let mut ok = remove_if_exists(&dest.join(DB_NAME));
        for sidecar in SIDECAR_NAMES {
            ok &= remove_if_exists(&dest.join(sidecar));
        }
        ok
    }

    // Best-effort recursive copy of everything in `src` EXCEPT the skip list.
    // Only the DB travels via the backup API; blobs (written atomically by
    // tor-dirmgr, which also tolerates vanished/orphaned blobs) and unknown
    // files are copied file-wise, so copy failures mean a refetch, not
    // corruption — hence warn-only.
    fn copy_rest_recursive(
        src: &std::path::Path,
        dest: &std::path::Path,
        skip: &[&str],
        log_prefix: &'static str,
    ) {
        if let Err(e) = std::fs::create_dir_all(dest) {
            tracing::warn!(
                error = %e,
                "{log_prefix}cannot create snapshot subdirectory"
            );
            return;
        }
        let entries = match std::fs::read_dir(src) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "{log_prefix}cannot list snapshot source dir"
                );
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "{log_prefix}cannot read snapshot source entry"
                    );
                    continue;
                }
            };
            let name = entry.file_name();
            if skip
                .iter()
                .any(|s| std::ffi::OsStr::new(s) == name.as_os_str())
            {
                continue;
            }
            let dest_path = dest.join(&name);
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => {
                    copy_rest_recursive(&entry.path(), &dest_path, skip, log_prefix)
                }
                Ok(_) => {
                    if let Err(e) = std::fs::copy(entry.path(), &dest_path) {
                        tracing::warn!(
                            error = %e,
                            file = %name.to_string_lossy(),
                            "{log_prefix}snapshot file copy failed; check client will refetch"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "{log_prefix}cannot stat snapshot source entry"
                    );
                }
            }
        }
    }

    // 1. Ensure the destination exists.
    if let Err(e) = std::fs::create_dir_all(dest) {
        tracing::warn!(
            error = %e,
            "{log_prefix}cannot create cache snapshot directory"
        );
        return false;
    }

    // 2. Scratch dirs can persist between batches: drop any stale snapshot
    // DB and sidecars first.
    if dest.join(DB_NAME).exists() && std::fs::remove_file(dest.join(DB_NAME)).is_err() {
        tracing::warn!("{log_prefix}cannot remove stale snapshot dir.sqlite3");
        return false;
    }
    for sidecar in SIDECAR_NAMES {
        let _ = std::fs::remove_file(dest.join(sidecar));
    }

    // 3. No live DB at all (fresh engine): leave dest EMPTY — an explicitly
    // clean empty cache dir the check client cold-starts in.
    let src_db = src.join(DB_NAME);
    if !src_db.exists() {
        return true;
    }

    // Open the live DB read-only (matches tor-dirmgr's own readonly store;
    // a hot-journal DB may refuse a read-only open — that lands in the
    // empty-cache fallback below).
    let src_conn = match rusqlite::Connection::open_with_flags(
        &src_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(conn) => conn,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "{log_prefix}cannot open live dir.sqlite3 read-only"
            );
            return if remove_db_and_sidecars(dest) {
                true
            } else {
                tracing::warn!("{log_prefix}cannot clean snapshot dir after failed open");
                false
            };
        }
    };

    let backup_result: Result<(), String> = {
        let dest_conn: Result<rusqlite::Connection, String> =
            match rusqlite::Connection::open(dest.join(DB_NAME)) {
                Ok(conn) => Ok(conn),
                Err(e) => Err(e.to_string()),
            };
        // Scoped so both connections are closed before any cleanup below.
        match dest_conn {
            Ok(mut dest_conn) => match rusqlite::backup::Backup::new(&src_conn, &mut dest_conn) {
                Ok(backup) => {
                    let deadline = std::time::Instant::now() + SNAPSHOT_BACKUP_DEADLINE;
                    loop {
                        // Checked on EVERY iteration, not just Busy/Locked:
                        // a source that keeps growing (concurrent writer)
                        // can make step() return `More` forever without
                        // ever reporting Busy/Locked, which would starve a
                        // deadline check placed only in that arm.
                        if std::time::Instant::now() >= deadline {
                            break Err("online backup did not finish within 15s".to_owned());
                        }
                        match backup.step(SNAPSHOT_BACKUP_PAGES_PER_STEP) {
                            Ok(rusqlite::backup::StepResult::Done) => break Ok(()),
                            Ok(rusqlite::backup::StepResult::More) => {}
                            Ok(
                                rusqlite::backup::StepResult::Busy
                                | rusqlite::backup::StepResult::Locked,
                            ) => {
                                std::thread::sleep(std::time::Duration::from_millis(10));
                            }
                            Err(e) => break Err(e.to_string()),
                            // StepResult is #[non_exhaustive]; treat any
                            // future variant like More (keep going).
                            Ok(_) => {}
                        }
                    }
                }
                Err(e) => Err(e.to_string()),
            },
            Err(e) => Err(e),
        }
    };
    drop(src_conn);

    if let Err(e) = backup_result {
        tracing::warn!(
            error = %e,
            "{log_prefix}sqlite online backup failed; falling back to an empty cache snapshot"
        );
        // Never keep a partial DB: wipe it and its sidecars, then serve an
        // empty cache dir instead.
        if !remove_db_and_sidecars(dest) {
            tracing::warn!("{log_prefix}cannot clean snapshot dir after failed backup");
            return false;
        }
        return true;
    }

    // 4. DB snapshot done: best-effort copy of the rest of the cache dir.
    copy_rest_recursive(src, dest, &REST_COPY_SKIP, log_prefix);
    true
}

#[cfg(test)]
mod tests {
    use super::snapshot_cache_dir;

    fn snapshot_cli(src: &std::path::Path, dest: &std::path::Path) -> bool {
        snapshot_cache_dir(src, dest, "circuit-verify: ")
    }

    fn snapshot_android(src: &std::path::Path, dest: &std::path::Path) -> bool {
        snapshot_cache_dir(src, dest, "bridge-verify: ")
    }

    /// Builds a small valid source cache DB at `dir/dir.sqlite3` with a
    /// `t(seq INTEGER PRIMARY KEY)` table of `n` rows.
    fn seed_source_db(dir: &std::path::Path, n: i64) {
        std::fs::create_dir_all(dir).expect("mkdir src");
        let conn = rusqlite::Connection::open(dir.join("dir.sqlite3")).expect("open src db");
        conn.execute_batch(
            "CREATE TABLE t(seq INTEGER PRIMARY KEY, payload BLOB);
             INSERT INTO t(seq, payload) VALUES (0, x'00');",
        )
        .expect("seed");
        for seq in 1..n {
            conn.execute(
                "INSERT INTO t(seq, payload) VALUES (?1, ?2)",
                rusqlite::params![seq, [0u8; 16]],
            )
            .expect("seed row");
        }
    }

    fn payload_for(seq: i64) -> [u8; 8192] {
        [(seq % 251) as u8; 8192]
    }

    // ---- Scenario moves: CLI side (apps/socks5-proxy bridge_verifier.rs) ----

    /// THE key test: while a writer keeps committing rows to the live DB, the
    /// snapshot must still yield a consistent, standalone SQLite file — the
    /// whole point of using the Online Backup API instead of a file copy.
    #[test]
    fn snapshot_is_consistent_under_concurrent_writes_cli() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("mkdir src");
        {
            let conn = rusqlite::Connection::open(src.join("dir.sqlite3")).expect("open src db");
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE t(seq INTEGER PRIMARY KEY, payload BLOB);",
            )
            .expect("create table");
            let mut stmt = conn
                .prepare("INSERT INTO t(seq, payload) VALUES (?1, ?2)")
                .expect("prepare insert");
            for seq in 0..200i64 {
                stmt.execute(rusqlite::params![seq, payload_for(seq)])
                    .expect("seed row");
            }
        }

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_stop = stop.clone();
        let writer_src = src.clone();
        let writer = std::thread::spawn(move || {
            let conn =
                rusqlite::Connection::open(writer_src.join("dir.sqlite3")).expect("open writer db");
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .expect("busy_timeout");
            let mut seq = 200i64;
            while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
                conn.execute(
                    "INSERT INTO t(seq, payload) VALUES (?1, ?2)",
                    rusqlite::params![seq, payload_for(seq)],
                )
                .expect("writer insert");
                // A realistic writer rate: tor-dirmgr commits routine
                // upkeep occasionally, not in an unthrottled tight loop.
                // An unthrottled writer can dirty pages faster than the
                // backup can copy them, so the source never stops growing
                // and the backup can never observe a quiet moment to finish.
                std::thread::sleep(std::time::Duration::from_millis(5));
                seq += 1;
            }
            seq
        });

        let dest = dir.path().join("dest");
        assert!(
            snapshot_cli(&src, &dest),
            "snapshot must succeed under concurrent writes"
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().expect("join writer");

        // The "check client opens it" proof: a fresh read-write connection.
        let snap = rusqlite::Connection::open(dest.join("dir.sqlite3")).expect("open snapshot db");
        let integrity: String = snap
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("integrity_check");
        assert_eq!(integrity, "ok", "snapshot must be a consistent DB");

        // Contiguous committed prefix starting at seq 0, no torn/garbage rows.
        let (count, max_seq): (i64, Option<i64>) = snap
            .query_row("SELECT COUNT(*), MAX(seq) FROM t", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("count/max");
        assert_eq!(count, max_seq.expect("nonempty") + 1, "contiguous prefix");
        let min_seq: i64 = snap
            .query_row("SELECT MIN(seq) FROM t", [], |row| row.get(0))
            .expect("min");
        assert_eq!(min_seq, 0, "prefix starts at 0");
        let mut stmt = snap
            .prepare("SELECT seq, payload FROM t")
            .expect("prepare scan");
        let rows: Vec<(i64, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query map")
            .collect::<Result<_, _>>()
            .expect("scan rows");
        for (seq, payload) in rows {
            assert_eq!(payload, payload_for(seq), "row {seq} payload intact");
        }

        // Check clients write descriptors: one INSERT into the snapshot works.
        snap.execute(
            "INSERT INTO t(seq, payload) VALUES (?1, ?2)",
            rusqlite::params![max_seq.unwrap() + 1, payload_for(0)],
        )
        .expect("insert into snapshot");
        drop(stmt);
        drop(snap);

        // Clean standalone snapshot: no sidecars travel with it.
        assert!(!dest.join("dir.sqlite3-wal").exists(), "no wal sidecar");
        assert!(
            !dest.join("dir.sqlite3-journal").exists(),
            "no journal sidecar"
        );
    }

    #[test]
    fn snapshot_falls_back_to_empty_cache_on_bad_source_db_cli() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("mkdir src");
        std::fs::write(src.join("dir.sqlite3"), b"definitely not a sqlite db").expect("garbage");

        let dest = dir.path().join("dest");
        assert!(
            snapshot_cli(&src, &dest),
            "empty-cache fallback is still a usable cache dir"
        );
        assert!(
            !dest.join("dir.sqlite3").exists(),
            "never ships the broken copy as the snapshot DB"
        );
    }

    #[test]
    fn snapshot_copies_blobs_but_not_lock_or_sidecars_cli() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        seed_source_db(&src, 5);
        std::fs::create_dir_all(src.join("dir_blobs/a")).expect("mkdir blobs");
        std::fs::write(src.join("dir_blobs/a/b.blob"), b"blob-a").expect("write blob");
        std::fs::write(src.join("dir_blobs/c.blob"), b"blob-c").expect("write blob");
        std::fs::write(src.join("dir.lock"), b"lock").expect("write lock");
        std::fs::write(src.join("dir.sqlite3-wal"), b"stale wal").expect("write wal");

        let dest = dir.path().join("dest");
        assert!(snapshot_cli(&src, &dest));

        // Snapshot DB is openable (trivial query) and usable.
        let snap = rusqlite::Connection::open(dest.join("dir.sqlite3")).expect("open snapshot db");
        let n: i64 = snap
            .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
            .expect("trivial query");
        assert_eq!(n, 5);
        drop(snap);

        // dir_blobs copied recursively; lock and sidecars never travel.
        assert_eq!(
            std::fs::read(dest.join("dir_blobs/a/b.blob")).expect("read blob a"),
            b"blob-a"
        );
        assert_eq!(
            std::fs::read(dest.join("dir_blobs/c.blob")).expect("read blob c"),
            b"blob-c"
        );
        assert!(!dest.join("dir.lock").exists(), "dir.lock must not travel");
        assert!(
            !dest.join("dir.sqlite3-wal").exists(),
            "sidecars must not travel with a backup-API snapshot"
        );
    }

    #[test]
    fn snapshot_missing_source_yields_empty_cache_cli() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("dest");
        assert!(
            snapshot_cli(&dir.path().join("does-not-exist"), &dest),
            "an empty cache dir is a valid fresh-client cache"
        );
        assert!(dest.is_dir(), "dest must exist");
        assert!(
            std::fs::read_dir(&dest)
                .expect("list dest")
                .next()
                .is_none(),
            "dest must be empty"
        );
    }

    // ---- Scenario moves: Android side (android-ffi jni_verify.rs) ----

    /// Cheap unique temp dir without `tempfile` (kept from the android side,
    /// where it was not a dev-dependency).
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bridge-verify-core-test-{}-{}-{}-{tag}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir temp dir");
        dir
    }

    /// THE key test: while a writer keeps committing rows to the live DB, the snapshot must
    /// still yield a consistent, standalone SQLite file -- the whole point of using the Online
    /// Backup API instead of a file copy.
    #[test]
    fn snapshot_is_consistent_under_concurrent_writes_android() {
        let base = unique_temp_dir("snapshot-concurrent");
        let src = base.join("src");
        std::fs::create_dir_all(&src).expect("mkdir src");
        {
            let conn = rusqlite::Connection::open(src.join("dir.sqlite3")).expect("open src db");
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE t(seq INTEGER PRIMARY KEY, payload BLOB);",
            )
            .expect("create table");
            let mut stmt = conn
                .prepare("INSERT INTO t(seq, payload) VALUES (?1, ?2)")
                .expect("prepare insert");
            for seq in 0..200i64 {
                stmt.execute(rusqlite::params![seq, payload_for(seq)])
                    .expect("seed row");
            }
        }

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_stop = stop.clone();
        let writer_src = src.clone();
        let writer = std::thread::spawn(move || {
            let conn =
                rusqlite::Connection::open(writer_src.join("dir.sqlite3")).expect("open writer db");
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .expect("busy_timeout");
            let mut seq = 200i64;
            while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
                conn.execute(
                    "INSERT INTO t(seq, payload) VALUES (?1, ?2)",
                    rusqlite::params![seq, payload_for(seq)],
                )
                .expect("writer insert");
                // A realistic writer rate: tor-dirmgr commits routine
                // upkeep occasionally, not in an unthrottled tight loop.
                // An unthrottled writer can dirty pages faster than the
                // backup can copy them, so the source never stops growing
                // and the backup can never observe a quiet moment to finish.
                std::thread::sleep(std::time::Duration::from_millis(5));
                seq += 1;
            }
            seq
        });

        let dest = base.join("dest");
        assert!(
            snapshot_android(&src, &dest),
            "snapshot must succeed under concurrent writes"
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().expect("join writer");

        // The "check client opens it" proof: a fresh read-write connection.
        let snap = rusqlite::Connection::open(dest.join("dir.sqlite3")).expect("open snapshot db");
        let integrity: String = snap
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("integrity_check");
        assert_eq!(integrity, "ok", "snapshot must be a consistent DB");

        // Contiguous committed prefix starting at seq 0, no torn/garbage rows.
        let (count, max_seq): (i64, Option<i64>) = snap
            .query_row("SELECT COUNT(*), MAX(seq) FROM t", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("count/max");
        assert_eq!(count, max_seq.expect("nonempty") + 1, "contiguous prefix");
        let min_seq: i64 = snap
            .query_row("SELECT MIN(seq) FROM t", [], |row| row.get(0))
            .expect("min");
        assert_eq!(min_seq, 0, "prefix starts at 0");
        let mut stmt = snap
            .prepare("SELECT seq, payload FROM t")
            .expect("prepare scan");
        let rows: Vec<(i64, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query map")
            .collect::<Result<_, _>>()
            .expect("scan rows");
        for (seq, payload) in rows {
            assert_eq!(payload, payload_for(seq), "row {seq} payload intact");
        }

        // Check clients write descriptors: one INSERT into the snapshot works.
        snap.execute(
            "INSERT INTO t(seq, payload) VALUES (?1, ?2)",
            rusqlite::params![max_seq.unwrap() + 1, payload_for(0)],
        )
        .expect("insert into snapshot");
        drop(stmt);
        drop(snap);

        // Clean standalone snapshot: no sidecars travel with it.
        assert!(!dest.join("dir.sqlite3-wal").exists(), "no wal sidecar");
        assert!(
            !dest.join("dir.sqlite3-journal").exists(),
            "no journal sidecar"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn snapshot_falls_back_to_empty_cache_on_bad_source_db_android() {
        let base = unique_temp_dir("snapshot-bad-src");
        let src = base.join("src");
        std::fs::create_dir_all(&src).expect("mkdir src");
        std::fs::write(src.join("dir.sqlite3"), b"definitely not a sqlite db").expect("garbage");

        let dest = base.join("dest");
        assert!(
            snapshot_android(&src, &dest),
            "empty-cache fallback is still a usable cache dir"
        );
        assert!(
            !dest.join("dir.sqlite3").exists(),
            "never ships the broken copy as the snapshot DB"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn snapshot_copies_blobs_but_not_lock_or_sidecars_android() {
        let base = unique_temp_dir("snapshot-blobs");
        let src = base.join("src");
        seed_source_db(&src, 5);
        std::fs::create_dir_all(src.join("dir_blobs/a")).expect("mkdir blobs");
        std::fs::write(src.join("dir_blobs/a/b.blob"), b"blob-a").expect("write blob");
        std::fs::write(src.join("dir_blobs/c.blob"), b"blob-c").expect("write blob");
        std::fs::write(src.join("dir.lock"), b"lock").expect("write lock");
        std::fs::write(src.join("dir.sqlite3-wal"), b"stale wal").expect("write wal");

        let dest = base.join("dest");
        assert!(snapshot_android(&src, &dest));

        // Snapshot DB is openable (trivial query) and usable.
        let snap = rusqlite::Connection::open(dest.join("dir.sqlite3")).expect("open snapshot db");
        let n: i64 = snap
            .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
            .expect("trivial query");
        assert_eq!(n, 5);
        drop(snap);

        // dir_blobs copied recursively; lock and sidecars never travel.
        assert_eq!(
            std::fs::read(dest.join("dir_blobs/a/b.blob")).expect("read blob a"),
            b"blob-a"
        );
        assert_eq!(
            std::fs::read(dest.join("dir_blobs/c.blob")).expect("read blob c"),
            b"blob-c"
        );
        assert!(!dest.join("dir.lock").exists(), "dir.lock must not travel");
        assert!(
            !dest.join("dir.sqlite3-wal").exists(),
            "sidecars must not travel with a backup-API snapshot"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn snapshot_missing_source_yields_empty_cache_android() {
        let base = unique_temp_dir("snapshot-missing-src");
        let dest = base.join("dest");
        assert!(
            snapshot_android(&base.join("does-not-exist"), &dest),
            "an empty cache dir is a valid fresh-client cache"
        );
        assert!(dest.is_dir(), "dest must exist");
        assert!(
            std::fs::read_dir(&dest)
                .expect("list dest")
                .next()
                .is_none(),
            "dest must be empty"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
