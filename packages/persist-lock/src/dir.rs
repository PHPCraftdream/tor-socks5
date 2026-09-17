//! Parent-directory helpers for durability of renames.

#[cfg(unix)]
use std::fs;
use std::io;
use std::path::Path;

/// Parent directory of `path` for directory-level fs operations.
///
/// `Path::parent` returns `Some("")` for a bare relative file name
/// (`Path::new("tor-socks5.ktav").parent()`), and `File::open("")` /
/// `read_dir("")` fail on every platform — the caller would silently skip a
/// durability guarantee that was supposed to cover the default configuration.
/// An empty parent is therefore normalised to `"."` (TS17-05).
pub fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// fsync the directory that records renames of `path` so the rename itself
/// survives a power loss. Callers treat this as best-effort; the `Result`
/// exists so tests can assert the directory was actually opened (a bare
/// file name must resolve to `.` and succeed on Unix).
#[cfg(unix)]
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    fs::File::open(parent_dir(path))?.sync_all()
}

/// Directories cannot be opened for fsync on this platform.
#[cfg(not(unix))]
pub fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_relative_file_name_resolves_to_dot() {
        assert_eq!(parent_dir(Path::new("tor-socks5.ktav")), Path::new("."));
    }

    #[test]
    fn nested_relative_path_yields_its_parent() {
        assert_eq!(parent_dir(Path::new("a/b/c.log")), Path::new("a/b"));
    }

    #[test]
    fn absolute_path_yields_its_parent() {
        assert_eq!(parent_dir(Path::new("/data/store.log")), Path::new("/data"));
    }

    #[test]
    fn empty_path_resolves_to_dot() {
        assert_eq!(parent_dir(Path::new("")), Path::new("."));
    }
}
