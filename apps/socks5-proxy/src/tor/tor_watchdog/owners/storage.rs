use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Result};

const LIMIT: usize = 15;
const MARKER: &[u8] = b"tor-socks5 owners-v1\n";
static QUARANTINE: Mutex<Vec<File>> = Mutex::new(Vec::new());

pub(super) struct Storage {
    pub(super) slot: usize,
    pub(super) state: PathBuf,
    pub(super) cache: PathBuf,
}

// На Windows запрещаем все точки повторной обработки, включая junction.
fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 || metadata.file_type().is_symlink()
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("не удалось проверить каталог хранилища"))?;
    if is_link(&metadata) || !metadata.is_dir() {
        bail!("недопустимый каталог хранилища");
    }
    Ok(())
}

/// `base` и пространство owners-v1 должны управляться администратором и быть
/// недоступны для записи клиентам и недоверенным локальным пользователям.
/// Проверки путей не атомарны и не защищают от конкурентной подмены файлов.
pub(super) fn acquire(base: &Path) -> Result<Storage> {
    acquire_with_quarantine(base, &QUARANTINE)
}

pub(super) fn acquire_with_quarantine(
    base: &Path,
    quarantine: &Mutex<Vec<File>>,
) -> Result<Storage> {
    let mut locks = quarantine
        .lock()
        .map_err(|_| anyhow!("карантин блокировок повреждён"))?;
    if locks.len() >= LIMIT {
        bail!("исчерпан процессный предел хранилищ владельцев; требуется перезапуск");
    }
    let root = base.join("owners-v1");
    fs::create_dir_all(&root).map_err(|_| anyhow!("не удалось создать пространство владельцев"))?;
    require_directory(&root)?;
    for slot in 1..=LIMIT {
        let lock_path = root.join(format!("{slot}.lock"));
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if is_link(&metadata) || !metadata.is_file() => {
                bail!("недопустимый файл блокировки владельца");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("не удалось проверить блокировку владельца"),
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|_| anyhow!("не удалось открыть блокировку владельца"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => continue,
            Err(std::fs::TryLockError::Error(_)) => {
                bail!("не удалось заблокировать хранилище владельца")
            }
        }
        // Arti не предоставляет join: даже при ошибке блокировка хранится до выхода процесса.
        locks.push(lock);
        drop(locks);
        let state = root.join(slot.to_string());
        match fs::create_dir(&state) {
            Ok(()) => {
                let mut marker = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(state.join(".owner-format"))
                    .map_err(|_| anyhow!("не удалось создать маркер хранилища"))?;
                marker
                    .write_all(MARKER)
                    .map_err(|_| anyhow!("не удалось записать маркер хранилища"))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => bail!("не удалось создать хранилище владельца"),
        }
        require_directory(&state)?;
        let marker_path = state.join(".owner-format");
        let metadata = fs::symlink_metadata(&marker_path)
            .map_err(|_| anyhow!("неизвестный формат хранилища владельца"))?;
        if is_link(&metadata)
            || !metadata.is_file()
            || fs::read(marker_path)
                .map_err(|_| anyhow!("неизвестный формат хранилища владельца"))?
                != MARKER
        {
            bail!("неизвестный формат хранилища владельца");
        }
        // Только известные подкаталоги Arti очищаются до создания нового клиента.
        // Карантин гарантирует отсутствие пользователей слота от прежнего процесса.
        for name in ["state", "cache", "pt_state"] {
            let path = state.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if is_link(&metadata) || !metadata.is_dir() {
                        bail!("недопустимый подкаталог хранилища");
                    }
                    fs::remove_dir_all(&path)
                        .map_err(|_| anyhow!("не удалось очистить хранилище владельца"))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => bail!("не удалось проверить подкаталог хранилища"),
            }
        }
        let cache = state.join("cache");
        fs::create_dir(&cache).map_err(|_| anyhow!("не удалось создать кэш владельца"))?;
        return Ok(Storage { slot, state, cache });
    }
    bail!("нет свободных хранилищ владельцев; требуется завершить другие процессы или перезапустить процесс")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_marker_does_not_delete_data() {
        let dir = tempfile::tempdir().unwrap();
        let slot = dir.path().join("owners-v1/1");
        fs::create_dir_all(slot.join("state")).unwrap();
        fs::write(slot.join(".owner-format"), b"foreign").unwrap();
        fs::write(slot.join("state/data"), b"keep").unwrap();
        let quarantine = Mutex::new(Vec::new());
        assert!(acquire_with_quarantine(dir.path(), &quarantine).is_err());
        assert_eq!(fs::read(slot.join("state/data")).unwrap(), b"keep");
    }

    #[test]
    fn busy_slot_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let first = Mutex::new(Vec::new());
        let second = Mutex::new(Vec::new());
        assert_eq!(acquire_with_quarantine(dir.path(), &first).unwrap().slot, 1);
        assert_eq!(
            acquire_with_quarantine(dir.path(), &second).unwrap().slot,
            2
        );
    }

    #[test]
    fn reuse_clears_owned_data_and_keeps_namespace_bounded() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..20 {
            // Освобождение имитирует выход процесса без живых клиентов Arti.
            let quarantine = Mutex::new(Vec::new());
            let storage = acquire_with_quarantine(dir.path(), &quarantine).unwrap();
            assert_eq!(storage.slot, 1);
            assert!(!storage.state.join("state").exists());
            assert!(!storage.state.join("pt_state").exists());
            assert!(!storage.cache.join("data").exists());
            assert_eq!(
                fs::read(storage.state.join(".owner-format")).unwrap(),
                MARKER
            );
            fs::create_dir(storage.state.join("state")).unwrap();
            fs::create_dir(storage.state.join("pt_state")).unwrap();
            fs::write(storage.state.join("state/data"), b"old").unwrap();
            fs::write(storage.state.join("pt_state/data"), b"old").unwrap();
            fs::write(storage.cache.join("data"), b"old").unwrap();
        }
        let root = dir.path().join("owners-v1");
        let entries: Vec<_> = fs::read_dir(root).unwrap().collect();
        assert!(entries.len() <= LIMIT * 2);
    }
}
