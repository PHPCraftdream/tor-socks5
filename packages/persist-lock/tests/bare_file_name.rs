//! TS17-05 regression: a BARE relative target name must not disable
//! cleanup or the parent-directory fsync. This file chdir's (process-global
//! state), so it must contain exactly one test — it cannot race siblings.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use persist_lock::{cleanup_temp_files, sync_parent_dir};

#[test]
fn bare_relative_target_names_are_cleaned_and_fsynced() {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-persist-lock-bare-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("sub/dir")).unwrap();

    let orig = std::env::current_dir().expect("read cwd");
    struct RestoreCwd(PathBuf);
    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }
    let _restore = RestoreCwd(orig);
    std::env::set_current_dir(&dir).expect("chdir");

    // Bare relative name.
    fs::write("store.log", b"target").unwrap();
    fs::write(".store.log.999.7.tmp", b"dead owner").unwrap();

    cleanup_temp_files(Path::new("store.log"));
    assert!(!Path::new(".store.log.999.7.tmp").exists(), "temp deleted");
    assert!(Path::new("store.log").exists(), "target kept");
    assert!(sync_parent_dir(Path::new("store.log")).is_ok());

    // Nested relative name — behaviour unchanged vs pre-fix.
    fs::write("sub/dir/data.log", b"target").unwrap();
    fs::write("sub/dir/.data.log.999.7.tmp", b"dead owner").unwrap();

    cleanup_temp_files(Path::new("sub/dir/data.log"));
    assert!(
        !Path::new("sub/dir/.data.log.999.7.tmp").exists(),
        "nested temp deleted"
    );
    assert!(Path::new("sub/dir/data.log").exists(), "nested target kept");
    assert!(sync_parent_dir(Path::new("sub/dir/data.log")).is_ok());

    drop(_restore);
    let _ = fs::remove_dir_all(&dir);
}
