use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PID_MARKER: &str = "owner-contract-pid";

struct Scan {
    found: Vec<(PathBuf, u32)>,
    error: Option<&'static str>,
}

#[derive(Default)]
pub(super) struct KnownChildren {
    pids: BTreeSet<u32>,
    scan_failed: bool,
}

pub(super) fn scan_child_pids(root: &Path) -> Result<Vec<(PathBuf, u32)>, &'static str> {
    let scan = scan_child_pids_partial(root);
    match scan.error {
        Some(error) => Err(error),
        None => Ok(scan.found),
    }
}

fn scan_child_pids_partial(root: &Path) -> Scan {
    fn walk(
        dir: &Path,
        depth: usize,
        visited: &mut usize,
        out: &mut Vec<(PathBuf, u32)>,
    ) -> Option<&'static str> {
        if depth > 12 {
            return Some("глубина PID-сканирования превышена");
        }
        let read_entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return Some("ошибка чтения PID-каталога"),
        };
        let mut entries = Vec::new();
        for entry in read_entries {
            *visited += 1;
            if *visited > 512 {
                return Some("превышен лимит записей PID-сканирования");
            }
            match entry {
                Ok(entry) => entries.push(entry),
                Err(_) => return Some("ошибка записи PID-каталога"),
            }
        }
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            let ty = match entry.file_type() {
                Ok(ty) => ty,
                Err(_) => return Some("ошибка типа записи PID-каталога"),
            };
            if ty.is_symlink() {
                return Some("символическая ссылка в PID-сканировании запрещена");
            }
            if ty.is_dir() {
                if let Some(error) = walk(&path, depth + 1, visited, out) {
                    return Some(error);
                }
            } else if ty.is_file() && entry.file_name() == "owner-contract-pid" {
                let text = match fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(_) => return Some("ошибка чтения PID-файла"),
                };
                let pid = match text.trim().parse() {
                    Ok(pid) => pid,
                    Err(_) => return Some("ошибка разбора PID-файла"),
                };
                out.push((path, pid));
            }
        }
        None
    }
    let mut found = Vec::new();
    let mut visited = 0;
    let error = walk(root, 0, &mut visited, &mut found);
    Scan { found, error }
}

impl KnownChildren {
    pub(super) fn refresh(&mut self, root: &Path) -> Result<(), &'static str> {
        let scan = scan_child_pids_partial(root);
        self.pids.extend(scan.found.into_iter().map(|(_, pid)| pid));
        if let Some(error) = scan.error {
            self.scan_failed = true;
            Err(error)
        } else {
            Ok(())
        }
    }
}

pub(super) async fn verify_children_gone(
    known: &mut KnownChildren,
    dir: &Path,
    total_deadline: tokio::time::Instant,
) -> Result<(), &'static str> {
    loop {
        let _ = known.refresh(dir);
        let mut alive = false;
        for pid in &known.pids {
            match fs::metadata(format!("/proc/{pid}")) {
                Ok(_) => alive = true,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(_) => known.scan_failed = true,
            }
        }
        if !alive {
            return if known.scan_failed {
                Err("PT PID scan failed")
            } else {
                Ok(())
            };
        }
        let now = tokio::time::Instant::now();
        if now >= total_deadline {
            return Err("PT children survived shutdown");
        }
        tokio::time::sleep_until((now + Duration::from_millis(500)).min(total_deadline)).await;
    }
}

#[tokio::test]
async fn pid_scan_error_keeps_partial_and_sticky_children() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    let known_path = a.join(PID_MARKER);
    fs::write(&known_path, std::process::id().to_string()).unwrap();
    fs::write(b.join(PID_MARKER), "not-a-pid").unwrap();
    let mut known = KnownChildren::default();
    assert!(known.refresh(dir.path()).is_err());
    assert!(known.scan_failed);
    assert!(known.pids.contains(&std::process::id()));
    assert!(
        verify_children_gone(&mut known, dir.path(), tokio::time::Instant::now())
            .await
            .is_err()
    );
    fs::remove_file(known_path).unwrap();
    assert!(known.refresh(dir.path()).is_err());
    assert!(known.pids.contains(&std::process::id()));
}
