use std::{
    ffi::OsString,
    fs,
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout_at, Instant},
};

const MAX_PATH: usize = 2048;
const MAX_PAYLOAD: usize = 4 * MAX_PATH + 2;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "direct-child deadline expired",
        ))
    } else {
        Ok(())
    }
}

/// cancel-safe: NO — timeout is terminal; partially completed I/O is not retried.
async fn bounded<T>(
    deadline: Instant,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    check_deadline(deadline)?;
    let result = timeout_at(deadline, operation).await;
    check_deadline(deadline)?;
    result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct-child deadline expired"))?
}

fn synchronous<T>(deadline: Instant, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    check_deadline(deadline)?;
    let result = operation();
    check_deadline(deadline)?;
    result
}

/// cancel-safe: NO — dropping loses framing state; the owned connection must close.
async fn read_line(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(64);
    loop {
        if line.len() == MAX_PAYLOAD {
            return Err(invalid("direct-child reply exceeds bound"));
        }

        let mut byte = [0u8; 1];
        let count = bounded(deadline, stream.read(&mut byte)).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "direct-child reply ended before newline",
            ));
        }

        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
}

fn nibble(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid("GROUP requires lowercase hexadecimal")),
    }
}

fn decode_group(frame: &[u8]) -> io::Result<PathBuf> {
    if frame.len() > MAX_PAYLOAD {
        return Err(invalid("GROUP frame exceeds bound"));
    }

    let encoded = frame
        .strip_prefix(b"GROUP ")
        .and_then(|body| body.strip_suffix(b"\n"))
        .ok_or_else(|| invalid("expected exact GROUP frame"))?;

    if encoded.is_empty() || encoded.len() > 2 * MAX_PATH || encoded.len() % 2 != 0 {
        return Err(invalid("invalid GROUP encoding length"));
    }

    let mut raw = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        let byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        if byte == 0 {
            return Err(invalid("GROUP path contains NUL"));
        }
        raw.push(byte);
    }

    Ok(PathBuf::from(OsString::from_vec(raw)))
}

fn canonical_directory(path: &Path, deadline: Instant) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid("group directory must be absolute"));
    }

    let resolved = synchronous(deadline, || fs::canonicalize(path))?;
    if resolved != path {
        return Err(invalid("group directory is not canonical"));
    }

    let metadata = synchronous(deadline, || fs::symlink_metadata(&resolved))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("group is not a nonsymlink directory"));
    }
    Ok(resolved)
}

// Matches direct_domain.py self_migrate/canonical under the same trusted,
// supervisor-owned stable-tree assumption. Canonicalize followed by open does
// not defend against an attacker concurrently replacing filesystem entries.
fn self_migrate(group: &Path, deadline: Instant) -> io::Result<()> {
    let group = canonical_directory(group, deadline)?;
    let mount = canonical_directory(Path::new("/sys/fs/cgroup"), deadline)?;

    let raw = group.as_os_str().as_bytes();
    if raw.is_empty() || raw.len() > MAX_PATH || raw.contains(&0) {
        return Err(invalid("canonical group path exceeds bound"));
    }

    let owner_name = group
        .parent()
        .and_then(Path::file_name)
        .ok_or_else(|| invalid("group has no owner directory"))?;
    let leaf = group
        .file_name()
        .ok_or_else(|| invalid("group has no leaf"))?;

    if !group.starts_with(&mount)
        || !owner_name.as_bytes().starts_with(b"pt-owner-audit-")
        || (leaf.as_bytes() != b"direct-0" && leaf.as_bytes() != b"direct-1")
    {
        return Err(invalid("invalid direct-child group"));
    }

    let target = group.join("cgroup.procs");
    let resolved = synchronous(deadline, || fs::canonicalize(&target))?;
    let metadata = synchronous(deadline, || fs::metadata(&target))?;
    if resolved != target || !metadata.is_file() {
        return Err(invalid("invalid cgroup.procs"));
    }

    // Unlike Python open("w"), do not create a vanished target.
    let mut output = synchronous(deadline, || {
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&target)
    })?;

    let written = synchronous(deadline, || output.write(b"0"))?;
    if written != 1 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete child self-migration write",
        ));
    }
    synchronous(deadline, || output.flush())
}

/// cancel-safe: NO — migration cannot be rolled back, and BIND/MOVED writes may
/// be partial when cancelled. Retain this exact future, or its owning actor,
/// through completion. Never drop and restart it after a competing select arm.
/// Any error is terminal; no protected child work may follow an error.
///
/// Synchronous filesystem calls detect expiry before and after each call; they
/// cannot be preempted. An external process/job lifetime bound remains necessary.
pub(super) async fn direct_child_gate(address: SocketAddr, deadline: Instant) -> io::Result<()> {
    direct_child_gate_with_migration(address, deadline, |group| self_migrate(group, deadline)).await
}

/// cancel-safe: NO — the same retained-operation contract as direct_child_gate.
/// The injected operation substitutes only migration, not framing or TCP I/O.
async fn direct_child_gate_with_migration(
    address: SocketAddr,
    deadline: Instant,
    migrate: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    check_deadline(deadline)?;
    let pid = std::process::id();
    if pid <= 1 {
        return Err(invalid(
            "direct child requires its real PID greater than one",
        ));
    }

    let mut stream = bounded(deadline, TcpStream::connect(address)).await?;
    let bind = format!("BIND {pid}\n");
    bounded(deadline, stream.write_all(bind.as_bytes())).await?;

    let initial = read_line(&mut stream, deadline).await?;
    let group = decode_group(&initial)?;

    synchronous(deadline, || migrate(&group))?;
    bounded(deadline, stream.write_all(b"MOVED\n")).await?;

    let final_reply = read_line(&mut stream, deadline).await?;
    if final_reply != b"OK\n" {
        return Err(invalid("direct-child final reply is not exact OK"));
    }
    check_deadline(deadline)
}

#[path = "direct_child_gate_tests.rs"]
mod tests;
