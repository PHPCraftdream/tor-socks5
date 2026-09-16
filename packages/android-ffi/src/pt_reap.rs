//! Android-side /proc plumbing for killing PT children of throwaway verify
//! clients by exact per-check ownership token: the unique
//! `TOR_PT_STATE_LOCATION` each check's PT child carries in
//! `/proc/<pid>/environ` (see `bridge_verify_core::pt_reap::pt_state_location_token`
//! for how that value is composed). Unlike a marker-copy scheme, nothing is
//! copied or made executable (Android W^X forbids executing scratch copies),
//! and unlike the old global marker registry, one batch's sweep can never
//! match another batch's children (different unique check dirs), the main
//! engine's PT (its state dir is the engine's own), or a recycled PID.
//!
//! Signal delivery is pidfd-bound: a stable OS handle is acquired for a pid
//! BEFORE the final environ revalidation, so the SIGKILL goes to the verified
//! process identity, never a recycled PID. pidfd requires Android API 31+
//! (bionic sys/pidfd.h); on older/unknown API levels NO pidfd cleanup runs --
//! the sweep reports `SweepFailure::PidfdUnsupported` (a leak is possible but
//! visible). Kernel-ENOSYS and EPERM also fail closed; no numeric-kill fallback.
//!
//! Why the late-child window is closed without a global registry: the only
//! code that can exec a check's PT binary is a task polled on that check's
//! own current-thread tokio runtime (tor-ptmgr's reactor drives
//! `spawn_from_config`); the stdout reader (tor-ptmgr-0.43.0/src/ipc.rs
//! `AsyncPtChild::new`) is a detached plain OS thread that never spawns
//! processes. Once the check's runtime is shut down or dropped, nothing can
//! spawn another child under this token.

/// Result of one sweep: only successful signal deliveries count as killed.
/// ESRCH is reported separately (target already gone); every other failure is
/// surfaced -- never swallowed, never a fallback to an unchecked numeric kill.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct KillReport {
    pub killed: usize,
    pub already_gone: usize,
    pub failures: Vec<SweepFailure>,
}

#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SweepFailure {
    /// Signalling a verified target failed with this errno.
    Signal { pid: u32, errno: i32 },
    /// The kernel has no pidfd support (pre-5.3): nothing was signalled at
    /// all, so leak reaping is impossible on this device until reported.
    PidfdUnsupported,
}

/// Why a stable handle could not be acquired for a pid.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PidfdOpenError {
    /// ESRCH: the process died between enumeration and handle acquisition.
    Gone,
    /// ENOSYS: kernel without pidfd support.
    Unsupported,
    /// Any other errno.
    Other(i32),
}

/// Why signalling a verified handle failed: `Gone` is the platform's
/// "already exited" (ESRCH on Linux, mapped from libc::ESRCH in the
/// android backend); anything else carries errno.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignalError {
    /// The bound process is already gone (ESRCH).
    Gone,
    /// Any other errno from the signalling syscall.
    Other(i32),
}

/// A stable OS handle bound to ONE process identity (a pidfd on Linux).
/// Signalling goes through the handle, so a PID recycled after verification
/// cannot redirect the signal. Dropping closes the underlying handle exactly
/// once, on every branch.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
pub(crate) trait OwnedSignalHandle {
    /// SIGKILL via the stable handle; `Err(SignalError::Gone)` means the
    /// bound process is already gone.
    fn kill(&mut self) -> Result<(), SignalError>;
}

/// Source of stable handles. `open` is called BEFORE final ownership
/// revalidation, so the handle is bound to the process that was verified,
/// not merely to a PID.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
pub(crate) trait ProcessSignals {
    fn open(&self, pid: u32) -> Result<Box<dyn OwnedSignalHandle>, PidfdOpenError>;
}

/// Sweeps verified targets: for each pid, acquire the stable handle FIRST
/// (binding the signal to the checked identity), then revalidate ownership
/// against the CURRENT process state, then signal via the handle. Order is
/// the whole point: a PID recycled between enumeration and revalidation is
/// rejected, and one recycled after revalidation still receives the signal
/// on the original (verified) process because delivery goes by handle.
/// The handle is closed on every branch via Drop (see `OwnedSignalHandle`).
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
pub(crate) fn sweep_owned_children(
    targets: impl IntoIterator<Item = u32>,
    token: &[u8],
    revalidate: &mut dyn FnMut(u32) -> Option<Vec<u8>>,
    signals: &dyn ProcessSignals,
) -> KillReport {
    let mut report = KillReport::default();
    for pid in targets {
        let mut handle = match signals.open(pid) {
            Ok(handle) => handle,
            // Died between enumeration and acquisition: no handle exists.
            Err(PidfdOpenError::Gone) => {
                report.already_gone += 1;
                continue;
            }
            // No pidfd support: no candidate can be signalled; stop without
            // falling back to an unchecked numeric kill.
            Err(PidfdOpenError::Unsupported) => {
                report.failures.push(SweepFailure::PidfdUnsupported);
                return report;
            }
            Err(PidfdOpenError::Other(e)) => {
                report.failures.push(SweepFailure::Signal { pid, errno: e });
                continue;
            }
        };
        // Revalidate AFTER the handle is bound: a recycled PID no longer
        // carries our exact token. Not a failure, not a kill; dropping the
        // handle (scope end) closes the stale identity's fd.
        if revalidate(pid).as_deref() != Some(token) {
            continue;
        }
        match handle.kill() {
            Ok(()) => report.killed += 1,
            Err(SignalError::Gone) => report.already_gone += 1,
            Err(SignalError::Other(errno)) => {
                report.failures.push(SweepFailure::Signal { pid, errno });
            }
        }
    }
    report
}

/// First `TASK_COMM_LEN - 1` (15) bytes of `path`'s file name -- what Linux
/// would report as the process's `comm` (field 2 of `/proc/<pid>/stat`,
/// truncated by the kernel to exactly this) if it exec'd `path`. Used only to
/// recognize a *PT-named* own child whose ownership is unprovable (see
/// [`kill_own_state_children`]); never as the ownership proof itself.
pub(crate) fn pt_binary_comm(pt_binary: &std::path::Path) -> Vec<u8> {
    #[cfg(unix)]
    let name = pt_binary
        .file_name()
        .map(std::os::unix::ffi::OsStrExt::as_bytes)
        .unwrap_or(&[])
        .to_vec();
    #[cfg(not(unix))]
    let name = pt_binary
        .file_name()
        .map(|n| n.to_string_lossy().into_owned().into_bytes())
        .unwrap_or_default();
    name.into_iter().take(15).collect()
}

/// A live own child together with its raw `/proc/<pid>/environ` blob (empty
/// on any read error -- the shared parser then reports ownership unproven).
#[cfg(target_os = "android")]
struct ChildProcEnv {
    proc: ChildProc,
    environ: Vec<u8>,
}

/// One live child process as observed in `/proc` (see
/// [`own_child_procs_with_environ`] for the android-only source).
#[cfg(target_os = "android")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ChildProc {
    pid: u32,
    ppid: u32,
    /// First 15 bytes of the executable's basename (kernel TASK_COMM_LEN
    /// truncation), from the `comm` field of `/proc/<pid>/stat`.
    comm: Vec<u8>,
}

/// Live direct children of this process with their environ blobs, read from
/// `/proc`. Linux's process tree has no concept of "which logical client
/// spawned this" -- every child of our own PID shows up here regardless of
/// which throwaway `TorTunnel` (or the long-lived main engine) started it.
/// Ownership is therefore established by the exact per-check state-location
/// token in each child's environ (via the shared
/// `bridge_verify_core::pt_reap::owned_process_targets` decision), not by
/// this listing.
#[cfg(target_os = "android")]
fn own_child_procs_with_environ() -> Vec<ChildProcEnv> {
    let my_pid = std::process::id();
    let mut children = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Format: "pid (comm) state ppid ...". `comm` can itself contain spaces or
        // parentheses, so take the bytes between the *first* '(' and the *last* ')'
        // before splitting the remaining fields.
        let Some((_, comm_and_rest)) = stat.split_once('(') else {
            continue;
        };
        let Some((comm, after_comm)) = comm_and_rest.rsplit_once(')') else {
            continue;
        };
        let mut fields = after_comm.split_whitespace();
        let _state = fields.next(); // field 3
        let Some(ppid) = fields.next().and_then(|s| s.parse::<u32>().ok()) else {
            continue; // field 4
        };
        if ppid == my_pid {
            children.push(ChildProcEnv {
                proc: ChildProc {
                    pid,
                    ppid,
                    comm: comm.as_bytes().iter().copied().take(15).collect(),
                },
                // Empty on error: an unreadable environ means ownership
                // unproven, and the shared decision fails closed on None.
                environ: std::fs::read(entry.path().join("environ")).unwrap_or_default(),
            });
        }
    }
    children
}

/// libc 0.2.186 ships no pidfd wrappers or constants for the android target,
/// so the sweep uses the stable kernel ABI numbers directly (man 2
/// pidfd_open, man 2 pidfd_send_signal): 434 and 424 on arm32/arm64/x86_64
/// alike. pidfd needs Linux >= 5.3; on older kernels acquisition fails with
/// ENOSYS and the sweep reports a PidfdUnsupported cleanup failure instead
/// of falling back to an unchecked numeric kill.
#[cfg(target_os = "android")]
const SYS_PIDFD_OPEN: libc::c_long = 434;
#[cfg(target_os = "android")]
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

/// A pidfd: a stable OS handle bound to one process identity. Closed exactly
/// once via Drop, on every branch.
#[cfg(target_os = "android")]
struct PidFd {
    fd: libc::c_int,
}

#[cfg(target_os = "android")]
impl Drop for PidFd {
    fn drop(&mut self) {
        // SAFETY: `fd` is a pidfd we own from pidfd_open; close(2) runs
        // exactly once from Drop on every branch.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(target_os = "android")]
impl OwnedSignalHandle for PidFd {
    fn kill(&mut self) -> Result<(), SignalError> {
        // SAFETY: fd is our live pidfd; NULL siginfo + flags 0 per the
        // pidfd_send_signal contract.
        let rc = unsafe {
            libc::syscall(
                SYS_PIDFD_SEND_SIGNAL,
                self.fd,
                libc::SIGKILL,
                std::ptr::null_mut::<libc::c_void>(),
                0u32,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        // Read errno immediately: the next libc call would clobber it.
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            libc::ESRCH => Err(SignalError::Gone),
            other => Err(SignalError::Other(other)),
        }
    }
}

/// pidfd-based [`ProcessSignals`] source for the Android sweep.
#[cfg(target_os = "android")]
struct PidSignals;

#[cfg(target_os = "android")]
impl ProcessSignals for PidSignals {
    fn open(&self, pid: u32) -> Result<Box<dyn OwnedSignalHandle>, PidfdOpenError> {
        // Decision code guarantees pid != 0; this is defense in depth for
        // the cast to c_int.
        let Ok(pid_c) = libc::c_int::try_from(pid) else {
            return Err(PidfdOpenError::Other(libc::EINVAL));
        };
        // SAFETY: pidfd_open takes (pid, flags) with flags 0; fd ownership
        // passes to PidFd.
        let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid_c, 0u32) } as libc::c_int;
        if fd >= 0 {
            return Ok(Box::new(PidFd { fd }));
        }
        // Read errno immediately: the next libc call would clobber it.
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            libc::ESRCH => Err(PidfdOpenError::Gone),
            libc::ENOSYS => Err(PidfdOpenError::Unsupported),
            other => Err(PidfdOpenError::Other(other)),
        }
    }
}

/// pidfd requires Android API 31+ (bionic sys/pidfd.h). Older app seccomp
/// policy can SIGSYS a raw pidfd syscall rather than fail with ENOSYS, so
/// support is decided BEFORE any pidfd syscall; an unknown API fails closed.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
pub(crate) fn pidfd_supported(api_level: Option<u32>) -> bool {
    matches!(api_level, Some(level) if level >= 31)
}

/// Reads `ro.build.version.sdk` via `__system_property_get`.
#[cfg(target_os = "android")]
fn android_api_level() -> Option<u32> {
    // libc::__system_property_get(name, buf) returns the value length (0 if
    // missing). PROP_VALUE_MAX is 92.
    let mut value = [0u8; 92];
    let name = b"ro.build.version.sdk\0";
    // SAFETY: NUL-terminated name; `value` is PROP_VALUE_MAX bytes.
    let len = unsafe {
        libc::__system_property_get(
            name.as_ptr().cast::<libc::c_char>(),
            value.as_mut_ptr().cast::<libc::c_char>(),
        )
    };
    if len <= 0 {
        return None;
    }
    std::str::from_utf8(&value[..len as usize])
        .ok()?
        .parse()
        .ok()
}

/// Gate BEFORE the sweep: when pidfd is unsupported (old/unknown Android
/// API), no /proc scan happens and the signaller is never opened — the
/// unsupported status is reported visibly instead.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
pub(crate) fn sweep_with_pidfd_gate(
    targets: impl IntoIterator<Item = u32>,
    token: &[u8],
    revalidate: &mut dyn FnMut(u32) -> Option<Vec<u8>>,
    signals: &dyn ProcessSignals,
    supported: bool,
) -> KillReport {
    if !supported {
        return KillReport {
            killed: 0,
            already_gone: 0,
            failures: vec![SweepFailure::PidfdUnsupported],
        };
    }
    sweep_owned_children(targets, token, revalidate, signals)
}

/// `SIGKILL`s this process's own children whose `/proc/<pid>/environ` carries
/// exactly `token` as `TOR_PT_STATE_LOCATION` -- the ownership token of ONE
/// bridge check's PT child (its unique check state dir; see
/// `bridge_verify_core::pt_reap::pt_state_location_token`). `pt_name` (the
/// 15-byte comm of the PT binary's file name) is used only to surface
/// ownership-unprovable PT-named children.
///
/// Because each check's token is unique per check dir, this can never match
/// another concurrent batch's children, the main engine's PT (its state dir
/// is the engine's own), or an unrelated process. Fail closed: an empty
/// token, a non-child, or an unreadable/differing environ kills nothing.
/// Signal delivery is pidfd-bound -- the stable handle is acquired before
/// final environ revalidation -- so a PID recycled between validation and
/// signalling cannot redirect the SIGKILL; unsupported or denied handle
/// acquisition is reported as a cleanup failure, never a numeric fallback.
pub(crate) fn kill_own_state_children(token: &[u8], pt_name: &[u8]) -> KillReport {
    kill_own_state_children_impl(token, pt_name)
}

#[cfg(target_os = "android")]
fn kill_own_state_children_impl(token: &[u8], pt_name: &[u8]) -> KillReport {
    let my_pid = std::process::id();
    let procs = own_child_procs_with_environ();

    // Surface PT-named own children whose environ could not be read (or
    // carries no state location): ownership is unprovable there -- this is
    // distinct from a child with a *different readable* location (e.g. the
    // main engine's own PT), which is simply not ours to kill.
    if !pt_name.is_empty() {
        for child in &procs {
            if child.proc.ppid == my_pid
                && child.proc.comm == pt_name
                && bridge_verify_core::pt_reap::environ_state_location(&child.environ).is_none()
            {
                tracing::warn!(
                    pid = child.proc.pid,
                    "PT-named own child carries no readable TOR_PT_STATE_LOCATION; \
                     ownership unprovable, not killed (fail closed)"
                );
            }
        }
    }

    let targets = bridge_verify_core::pt_reap::owned_process_targets(
        procs.iter().map(|c| {
            (
                c.proc.pid,
                c.proc.ppid,
                bridge_verify_core::pt_reap::environ_state_location(&c.environ).map(|v| v.to_vec()),
            )
        }),
        my_pid,
        token,
    );
    sweep_with_pidfd_gate(
        targets,
        token,
        &mut |pid| {
            std::fs::read(format!("/proc/{pid}/environ"))
                .ok()
                .and_then(|bytes| {
                    bridge_verify_core::pt_reap::environ_state_location(&bytes).map(|v| v.to_vec())
                })
        },
        &PidSignals,
        pidfd_supported(android_api_level()),
    )
}

#[cfg(not(target_os = "android"))]
fn kill_own_state_children_impl(token: &[u8], pt_name: &[u8]) -> KillReport {
    // Host builds never spawn a real PT child, so there is nothing to reap.
    let _ = (token, pt_name);
    KillReport::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The /proc environ kill path can only be validated on an Android device
    // (device-only validation limit); host builds test only this pure helper.
    #[test]
    fn pt_binary_comm_truncates_to_15_bytes() {
        // "libtorpthelper.so" is 17 bytes; the first 15 cut mid-extension.
        let comm = pt_binary_comm(std::path::Path::new(
            "/data/app/org.torproject/lib/libtorpthelper.so",
        ));
        assert_eq!(comm, b"libtorpthelper.");
        assert_eq!(comm.len(), 15);
    }

    /// Deterministic fake signal source. The event log is shared with the
    /// fake handles via Arc (the fake is per-sweep; each test builds one).
    #[derive(Default)]
    struct FakeSignals {
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        /// pid -> what open() returns
        open_result: std::collections::HashMap<u32, Result<(), PidfdOpenError>>,
        /// pid -> what the handle's kill() returns
        kill_result: std::collections::HashMap<u32, Result<(), SignalError>>,
    }

    struct FakeHandle {
        pid: u32,
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        result: Result<(), SignalError>,
    }

    impl OwnedSignalHandle for FakeHandle {
        fn kill(&mut self) -> Result<(), SignalError> {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("kill:{}", self.pid));
            self.result.clone()
        }
    }

    impl Drop for FakeHandle {
        fn drop(&mut self) {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("close:{}", self.pid));
        }
    }

    impl ProcessSignals for FakeSignals {
        fn open(&self, pid: u32) -> Result<Box<dyn OwnedSignalHandle>, PidfdOpenError> {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("open:{pid}"));
            if let Some(Err(e)) = self.open_result.get(&pid) {
                return Err(e.clone());
            }
            Ok(Box::new(FakeHandle {
                pid,
                events: std::sync::Arc::clone(&self.events),
                result: self.kill_result.get(&pid).cloned().unwrap_or(Ok(())),
            }))
        }
    }

    impl FakeSignals {
        fn events(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    fn tok() -> Vec<u8> {
        b"tok".to_vec()
    }

    fn sweep(
        targets: &[u32],
        revalidate: impl FnMut(u32) -> Option<Vec<u8>>,
        signals: &FakeSignals,
    ) -> KillReport {
        let mut revalidate = revalidate;
        sweep_owned_children(targets.to_vec(), b"tok", &mut revalidate, signals)
    }

    #[test]
    fn sweep_signals_verified_target_via_handle() {
        let sig = FakeSignals::default();
        let report = sweep(&[42], |pid| (pid == 42).then(tok), &sig);
        assert_eq!(report.killed, 1);
        assert_eq!(report.already_gone, 0);
        assert!(report.failures.is_empty());
        let events = sig.events();
        let open = events.iter().position(|e| e == "open:42").unwrap();
        let kill = events.iter().position(|e| e == "kill:42").unwrap();
        assert!(open < kill);
        assert_eq!(
            events.iter().filter(|e| **e == "close:42").count(),
            1,
            "handle closed exactly once"
        );
    }

    #[test]
    fn sweep_rejects_recycled_pid_at_revalidation() {
        let sig = FakeSignals::default();
        let report = sweep(&[42], |_| None, &sig);
        assert_eq!(report.killed, 0);
        assert!(report.failures.is_empty());
        let events = sig.events();
        assert!(!events.contains(&"kill:42".to_string()));
        assert!(events.contains(&"close:42".to_string()));
    }

    #[test]
    fn sweep_reports_esrch_as_already_gone() {
        let sig = FakeSignals {
            kill_result: [(42u32, Err(SignalError::Gone))].into(),
            ..FakeSignals::default()
        };
        let report = sweep(&[42], |_| Some(tok()), &sig);
        assert_eq!(report.already_gone, 1);
        assert_eq!(report.killed, 0);
        assert!(report.failures.is_empty());
        assert!(sig.events().contains(&"close:42".to_string()));
    }

    #[test]
    fn sweep_reports_non_esrch_kill_failure() {
        let sig = FakeSignals {
            kill_result: [(42u32, Err(SignalError::Other(7)))].into(),
            ..FakeSignals::default()
        };
        let report = sweep(&[42], |_| Some(tok()), &sig);
        assert_eq!(report.killed, 0, "no misleading success");
        assert_eq!(
            report.failures,
            vec![SweepFailure::Signal { pid: 42, errno: 7 }]
        );
        assert!(sig.events().contains(&"close:42".to_string()));
    }

    #[test]
    fn sweep_reports_unsupported_kernel_without_signalling_anything() {
        let sig = FakeSignals {
            open_result: [(7u32, Err(PidfdOpenError::Unsupported))].into(),
            ..FakeSignals::default()
        };
        let report = sweep(&[7, 8], |_| Some(tok()), &sig);
        assert_eq!(report.killed, 0);
        assert_eq!(report.failures, vec![SweepFailure::PidfdUnsupported]);
        let events = sig.events();
        assert!(!events.contains(&"open:8".to_string()), "loop stopped");
        assert!(!events.contains(&"kill:8".to_string()));
    }

    #[test]
    fn sweep_reports_gone_target_before_revalidation() {
        let sig = FakeSignals {
            open_result: [(42u32, Err(PidfdOpenError::Gone))].into(),
            ..FakeSignals::default()
        };
        let revalidated = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&revalidated);
        let report = sweep(
            &[42],
            |pid| {
                seen.lock().unwrap_or_else(|e| e.into_inner()).push(pid);
                Some(tok())
            },
            &sig,
        );
        assert_eq!(report.already_gone, 1);
        assert!(report.failures.is_empty());
        assert!(
            revalidated
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "no revalidate call for a Gone target"
        );
        let events = sig.events();
        assert!(events.contains(&"open:42".to_string()));
        assert!(!events.contains(&"close:42".to_string()), "nothing opened");
    }

    #[test]
    fn sweep_continues_after_per_pid_open_failure() {
        let sig = FakeSignals {
            open_result: [(1u32, Err(PidfdOpenError::Other(1)))].into(),
            ..FakeSignals::default()
        };
        let report = sweep(&[1, 2], |_| Some(tok()), &sig);
        assert_eq!(
            report.failures,
            vec![SweepFailure::Signal { pid: 1, errno: 1 }]
        );
        assert_eq!(report.killed, 1);
    }

    #[test]
    fn sweep_revalidates_each_target_exactly_once() {
        let sig = FakeSignals::default();
        let mut seen: Vec<u32> = Vec::new();
        let mut revalidate = |pid: u32| {
            seen.push(pid);
            Some(tok())
        };
        let report = sweep_owned_children(vec![3, 4, 5], b"tok", &mut revalidate, &sig);
        assert_eq!(report.killed, 3);
        assert_eq!(seen, vec![3, 4, 5]);
    }

    #[test]
    fn pidfd_gate_requires_api_31() {
        assert!(!pidfd_supported(None));
        assert!(!pidfd_supported(Some(30)));
        assert!(pidfd_supported(Some(31)));
        assert!(pidfd_supported(Some(36)));
    }

    #[test]
    fn gate_blocks_signaller_before_open() {
        let sig = FakeSignals::default();
        let mut revalidate = |_| Some(tok());
        let report = sweep_with_pidfd_gate([42u32], b"tok", &mut revalidate, &sig, false);
        assert_eq!(report.killed, 0);
        assert_eq!(report.already_gone, 0);
        assert_eq!(report.failures, vec![SweepFailure::PidfdUnsupported]);
        assert!(
            sig.events().is_empty(),
            "opener must never run when the gate is closed"
        );
    }
}
