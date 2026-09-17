//! Real second-process regression test for TS17-01: a temp file locked by a
//! LIVE foreign process must survive reader-side cleanup, and must be
//! cleaned once that process is gone. This is exactly the case the pre-fix
//! `pid != std::process::id()` heuristic got wrong.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use persist_lock::{cleanup_temp_files, parse_temp_name, TempFileGuard};

const CHILD_ENV: &str = "PERSIST_LOCK_CHILD";
const DELIM: &str = "::";

/// When run with `PERSIST_LOCK_CHILD` set, this process is the child: it
/// parks holding an exclusive lock on a canonical temp until released.
/// Without the env var it is an ordinary (no-op) test.
#[test]
fn cross_process_child_helper_must_be_a_noop_without_env() {
    let Some(spec) = std::env::var(CHILD_ENV).ok() else {
        return;
    };
    let (dir, target) = spec.split_once(DELIM).expect("env spec format");
    let dir = PathBuf::from(dir);
    let target = PathBuf::from(target);

    let mut guard = TempFileGuard::create(&target, 1).expect("child create guard");
    guard.write_all(b"child data").expect("child write");

    fs::write(dir.join("child-ready"), b"").expect("write ready marker");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !dir.join("child-release").exists() {
        assert!(
            Instant::now() < deadline,
            "child: timed out waiting for release"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    guard.finish().expect("child finish");
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn child_output(child: &mut ChildGuard) -> String {
    let mut out = String::new();
    if let Some(mut stdout) = child.0.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    if let Some(mut stderr) = child.0.stderr.take() {
        let _ = stderr.read_to_string(&mut out);
    }
    out
}

#[test]
fn locked_foreign_temp_survives_cleanup_and_is_cleaned_after_exit() {
    let dir = unique_dir("persist-lock-cross");
    let target = dir.join("store.log");

    // Malformed names must survive BOTH cleanups.
    let malformed = dir.join(".store.log.not-a-pid.1.tmp");
    fs::write(&malformed, b"malformed").unwrap();

    let spec = format!("{}{}{}", dir.display(), DELIM, target.display());
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cross_process_child_helper_must_be_a_noop_without_env",
            "--test-threads",
            "1",
        ])
        .env(CHILD_ENV, &spec)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let mut child = ChildGuard(child);

    assert!(
        wait_for(&dir.join("child-ready"), Duration::from_secs(15)),
        "child never signalled ready; output:\n{}",
        child_output(&mut child)
    );

    // The child (a different process) holds the lock on the canonical temp.
    let mut tmps: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(parse_canonical)
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(tmps.len(), 1, "exactly one canonical temp expected");
    let temp = tmps.pop().unwrap();
    assert!(
        parse_canonical(temp.file_name().unwrap().to_str().unwrap()),
        "temp name must be canonical"
    );

    cleanup_temp_files(&target);
    assert!(
        temp.exists(),
        "TS17-01: a LIVE foreign writer's temp must survive cleanup"
    );
    assert!(malformed.exists(), "malformed name survives first cleanup");

    // Release the child and let it finish its save.
    fs::write(dir.join("child-release"), b"").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Ok(Some(status)) = child.0.try_wait() {
            break status;
        }
        assert!(Instant::now() < deadline, "child did not exit in time");
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(status.success(), "child failed: {:?}", status);

    cleanup_temp_files(&target);
    assert!(
        !temp.exists(),
        "after the owner died the temp must be cleaned"
    );
    assert!(malformed.exists(), "malformed name survives second cleanup");
    assert!(
        target.exists(),
        "child's finished save published the target"
    );
    assert_eq!(fs::read(&target).unwrap(), b"child data");

    let _ = fs::remove_dir_all(&dir);
}

/// Local helper so the test can assert canonicity without exposing internals.
fn parse_canonical(name: &str) -> bool {
    parse_temp_name(name, "store.log").is_some()
}
