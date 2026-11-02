//! Cancellation-safe EOF detection for the PT manager's standard input.
//!
//! This module owns the only stdin reader used by `lyrebird`. Do not call it
//! concurrently with another stdin reader: on Unix it temporarily enables
//! nonblocking mode on a duplicate of stdin (which shares the open file
//! description). Windows uses readiness probes without changing handle modes.

use std::io;

/// Waits until the process's standard input reaches EOF.
///
/// The managed-PT pipe paths contain no spawned task or pending blocking
/// operation. Dropping the future unregisters its descriptor/handle and
/// restores the temporary mode before returning control to the caller.
/// Regular files and non-terminal devices use direct reads because they have
/// no portable readiness source; those reads can briefly block on unusual
/// devices and are not the managed-PT path.
///
/// cancel-safe: yes — cancellation only drops the local descriptor/handle
/// wrapper; no read is left pending elsewhere.
pub(crate) async fn wait_stdin_close() -> io::Result<()> {
    imp::wait_stdin_close().await
}

#[cfg(unix)]
mod imp {
    use super::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use tokio::io::{unix::AsyncFd, Interest};

    const READ_BUFFER_LEN: usize = 4096;

    struct StdinFd {
        fd: OwnedFd,
        original_flags: libc::c_int,
    }

    impl AsRawFd for StdinFd {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl Drop for StdinFd {
        fn drop(&mut self) {
            // SAFETY: `self.fd` is an open descriptor created by `dup`, and
            // the caller contract excludes concurrent stdin readers. Restoring
            // its original flags before closing the duplicate also restores
            // the shared open file description for the process's stdin.
            unsafe {
                let _ = libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, self.original_flags);
            }
        }
    }

    fn read_once(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buffer is a valid writable slice for the specified length;
        // fd is the live duplicate held by StdinFd for the whole call.
        let result = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    async fn wait_fd_close(fd: RawFd) -> io::Result<()> {
        let watched = duplicate_fd(fd)?;
        if is_immediate_fd(fd)? {
            return wait_immediate(watched).await;
        }

        let async_fd = AsyncFd::with_interest(watched, Interest::READABLE)?;
        let mut buffer = [0_u8; READ_BUFFER_LEN];
        loop {
            let read = loop {
                match async_fd
                    .async_io(Interest::READABLE, |inner| {
                        read_once(inner.as_raw_fd(), &mut buffer)
                    })
                    .await
                {
                    Ok(read) => break read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            };
            if read == 0 {
                return Ok(());
            }
        }
    }

    fn duplicate_fd(source: RawFd) -> io::Result<StdinFd> {
        // Tests pass a raw pipe descriptor; the production path passes stdin.
        // Keep the duplication logic in one place so neither path can close a
        // descriptor it merely borrowed.
        // SAFETY: source is borrowed from the caller and F_GETFL does not
        // mutate the descriptor.
        let original_flags = unsafe { libc::fcntl(source, libc::F_GETFL) };
        if original_flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: source is valid for the duration of this call. F_DUPFD_CLOEXEC
        // returns a fresh descriptor owned by this function on success.
        let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: duplicate is the fresh descriptor returned above. The
        // caller contract excludes concurrent stdin readers while flags are
        // temporarily changed.
        let set_result =
            unsafe { libc::fcntl(duplicate, libc::F_SETFL, original_flags | libc::O_NONBLOCK) };
        if set_result == -1 {
            let error = io::Error::last_os_error();
            // SAFETY: duplicate is owned by this function and has not been
            // wrapped, so this is the sole close operation.
            unsafe {
                libc::close(duplicate);
            }
            return Err(error);
        }
        // SAFETY: duplicate is valid and uniquely owned by this function.
        let fd = unsafe { OwnedFd::from_raw_fd(duplicate) };
        Ok(StdinFd { fd, original_flags })
    }

    fn is_immediate_fd(fd: RawFd) -> io::Result<bool> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat points to writable storage of the exact libc::stat
        // type, and fd remains borrowed by the caller.
        let result = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstat returned success, so stat has been initialized.
        let stat = unsafe { stat.assume_init() };
        let kind = stat.st_mode & libc::S_IFMT;
        if kind == libc::S_IFREG {
            return Ok(true);
        }
        if kind == libc::S_IFCHR {
            // Terminals remain readiness-driven; devices such as /dev/null
            // complete synchronously and cannot be registered with epoll.
            // SAFETY: fd is a valid borrowed descriptor.
            let terminal = unsafe { libc::isatty(fd) } == 1;
            return Ok(!terminal);
        }
        Ok(false)
    }

    async fn wait_immediate(watched: StdinFd) -> io::Result<()> {
        let fd = watched.as_raw_fd();
        let mut buffer = [0_u8; READ_BUFFER_LEN];
        loop {
            match read_once(fd, &mut buffer) {
                Ok(0) => return Ok(()),
                Ok(_) => tokio::task::yield_now().await,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) async fn wait_stdin_close() -> io::Result<()> {
        let stdin = std::io::stdin();
        wait_fd_close(stdin.as_raw_fd()).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::time::Duration;

        fn pipe() -> (OwnedFd, OwnedFd) {
            let mut fds = [0; 2];
            // SAFETY: fds points to two writable ints and is initialized by
            // pipe on success; each result is wrapped exactly once below.
            let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(result, 0);
            // SAFETY: pipe returned two distinct owned descriptors.
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
        }

        #[tokio::test]
        async fn returns_on_pipe_eof() {
            let (reader, writer) = pipe();
            let future = wait_fd_close(reader.as_raw_fd());
            drop(writer);
            future.await.expect("pipe EOF should be observed");
        }

        #[tokio::test]
        async fn cancellation_does_not_leave_a_read_pending() {
            let (reader, writer) = pipe();
            // SAFETY: reader is a valid borrowed descriptor and F_GETFL does
            // not mutate it.
            let original_flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
            let result =
                tokio::time::timeout(Duration::from_millis(25), wait_fd_close(reader.as_raw_fd()))
                    .await;
            assert!(result.is_err(), "open pipe must not report EOF");

            // The duplicate watcher must have restored the shared open-file
            // description before cancellation returned.
            // SAFETY: reader remains owned by this test and F_GETFL is read-only.
            let restored_flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(restored_flags, original_flags);

            drop(reader);
            drop(writer);
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::io;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;

    use tokio::time::sleep;
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileType, ReadFile, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE,
    };
    use windows_sys::Win32::System::Console::GetConsoleMode;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    const READ_BUFFER_LEN: u32 = 4096;
    const ERROR_BROKEN_PIPE: u32 = 109;
    const ERROR_NO_DATA: u32 = 232;
    const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
    const ERROR_INVALID_HANDLE: u32 = 6;

    fn read_ready_pipe(handle: HANDLE, buffer: &mut [u8]) -> io::Result<usize> {
        let mut available = 0;
        // SAFETY: the caller owns the readable pipe handle; available is
        // writable. Exclusive stdin reading excludes concurrent blocking IO.
        let ok = unsafe {
            PeekNamedPipe(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => Ok(0),
                _ => Err(error),
            };
        }
        if available == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // No other reader can consume these bytes between the probe and read.
        let length = buffer.len().min(available as usize);
        read_pipe(handle, &mut buffer[..length])
    }

    fn read_pipe(handle: HANDLE, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read = 0_u32;
        // SAFETY: buffer is valid writable storage, handle is a borrowed stdin
        // handle, and the null OVERLAPPED pointer is correct for this
        // synchronous handle. Pipe reads are bounded to probed available bytes.
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(read as usize);
        }
        // SAFETY: GetLastError has no pointer arguments and reads the calling
        // thread's last Win32 error value.
        let code = unsafe { GetLastError() };
        match code {
            ERROR_NO_DATA => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED => Ok(0),
            _ => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    async fn wait_pipe<H>(owner: H) -> io::Result<()>
    where
        H: AsRawHandle + Send,
    {
        let mut buffer = [0_u8; READ_BUFFER_LEN as usize];
        loop {
            let read = {
                let handle = owner.as_raw_handle();
                read_ready_pipe(handle, &mut buffer)
            };
            match read {
                Ok(0) => return Ok(()),
                Ok(_) => tokio::task::yield_now().await,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    async fn wait_file<H>(owner: H) -> io::Result<()>
    where
        H: AsRawHandle + Send,
    {
        let mut buffer = [0_u8; READ_BUFFER_LEN as usize];
        loop {
            let read = {
                let handle = owner.as_raw_handle();
                read_pipe(handle, &mut buffer)
            };
            match read {
                Ok(0) => return Ok(()),
                Ok(_) => tokio::task::yield_now().await,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) async fn wait_stdin_close() -> io::Result<()> {
        let stdin = std::io::stdin();
        // SAFETY: handle is borrowed from the live Stdin owner.
        let file_type = unsafe { GetFileType(stdin.as_raw_handle()) };
        match file_type {
            FILE_TYPE_PIPE => wait_pipe(stdin).await,
            FILE_TYPE_DISK => wait_file(stdin).await,
            FILE_TYPE_CHAR => {
                let mut mode = 0_u32;
                // SAFETY: handle is borrowed and mode is writable storage.
                let console = unsafe { GetConsoleMode(stdin.as_raw_handle(), &mut mode) } != 0;
                if console {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "console stdin has no cancellable EOF operation",
                    ));
                }
                wait_file(stdin).await
            }
            _ => {
                // SAFETY: GetLastError has no pointer arguments and reads the
                // calling thread's last Win32 error value.
                let code = unsafe { GetLastError() };
                if code == ERROR_INVALID_HANDLE {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(code as i32))
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
        use std::time::Duration;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::WriteFile;
        use windows_sys::Win32::System::Pipes::{CreatePipe, GetNamedPipeHandleStateW};

        struct TestPipe {
            reader: OwnedHandle,
            writer: OwnedHandle,
        }

        fn anonymous_pipe() -> TestPipe {
            let mut reader = std::ptr::null_mut();
            let mut writer = std::ptr::null_mut();
            // SAFETY: both output pointers refer to writable HANDLE storage;
            // null security attributes request the process default, and zero
            // size selects the system default pipe buffer.
            let ok = unsafe {
                CreatePipe(
                    &mut reader,
                    &mut writer,
                    std::ptr::null::<SECURITY_ATTRIBUTES>(),
                    0,
                )
            };
            assert_ne!(ok, 0);
            // SAFETY: CreatePipe returned two distinct owned handles.
            let reader = unsafe { OwnedHandle::from_raw_handle(reader) };
            // SAFETY: the second successful output is independently owned.
            let writer = unsafe { OwnedHandle::from_raw_handle(writer) };
            TestPipe { reader, writer }
        }

        fn pipe_mode(handle: &OwnedHandle) -> u32 {
            let mut mode = 0_u32;
            // SAFETY: handle is valid and mode points to writable storage.
            let ok = unsafe {
                GetNamedPipeHandleStateW(
                    handle.as_raw_handle(),
                    &mut mode,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                )
            };
            assert_ne!(ok, 0);
            mode
        }

        fn assert_send<T: Send>(_: T) {}

        #[test]
        fn watcher_future_is_send() {
            assert_send(wait_stdin_close());
        }

        #[tokio::test]
        async fn pipe_mode_is_unchanged_after_cancellation() {
            let pipe = anonymous_pipe();
            let original = pipe_mode(&pipe.reader);
            let result = tokio::time::timeout(
                Duration::from_millis(40),
                wait_pipe(pipe.reader.as_handle()),
            )
            .await;
            assert!(result.is_err(), "open pipe must remain pending");
            assert_eq!(pipe_mode(&pipe.reader), original);
        }

        #[tokio::test]
        async fn returns_on_anonymous_pipe_eof() {
            let pipe = anonymous_pipe();
            drop(pipe.writer);
            wait_pipe(pipe.reader)
                .await
                .expect("pipe EOF should be observed");
        }

        #[tokio::test]
        async fn cancellation_drops_pending_pipe_watcher() {
            let pipe = anonymous_pipe();
            let result =
                tokio::time::timeout(Duration::from_millis(40), wait_pipe(pipe.reader)).await;
            assert!(result.is_err(), "open pipe must not report EOF");

            let byte = [7_u8];
            let mut written = 0_u32;
            // SAFETY: the writer handle and byte buffer are valid, and this
            // synchronous write is a one-byte resource-closure probe.
            let ok = unsafe {
                WriteFile(
                    pipe.writer.as_raw_handle(),
                    byte.as_ptr(),
                    byte.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(ok, 0, "cancellation must close the reader handle");
            // SAFETY: GetLastError has no pointer arguments and reads the
            // calling thread's last Win32 error value.
            let error = unsafe { GetLastError() };
            assert!(
                matches!(error, ERROR_NO_DATA | ERROR_BROKEN_PIPE),
                "closed pipe writer returned unexpected error: {error}"
            );
            drop(pipe.writer);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::io;

    pub(crate) async fn wait_stdin_close() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cancellable stdin EOF detection is unsupported on this platform",
        ))
    }
}
