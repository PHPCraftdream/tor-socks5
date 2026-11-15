//! Process lifetime safety net: [`bind_child_processes_to_self`] is called
//! once at startup. On Windows it puts our process into a Job Object with
//! `KILL_ON_JOB_CLOSE`, so every child arti spawns (the lyrebird PT) is
//! destroyed when we exit — clean exit, panic, `taskkill /F`, OS shutdown,
//! all the same. This is the safety net for unclean termination.

/// Install OS-level guarantees that our child processes do not outlive us.
/// Safe to call multiple times; failures are logged and tolerated (the
/// proxy still runs, we just lose the safety net on hard termination).
#[cfg(windows)]
pub fn bind_child_processes_to_self() {
    use std::mem::{size_of, zeroed};
    use std::ptr::null;

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: every call below is Win32 FFI used per its documented contract:
    // - CreateJobObjectW(NULL, NULL) creates an anonymous unnamed job object;
    //   its returned HANDLE is checked against both NULL and INVALID_HANDLE_VALUE
    //   before any further use.
    // - `info` is a fully-initialized #[repr(C)] JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
    //   the all-zero bit pattern from `zeroed()` is valid for it (all fields are
    //   integers / nullable HANDLEs), and we set only LimitFlags before the call.
    // - SetInformationJobObject receives a pointer to that live local plus its exact
    //   byte length; the buffer is read-only for the duration of the call and outlives it.
    // - GetCurrentProcess returns a pseudo-handle valid for AssignProcessToJobObject.
    // - The job HANDLE is intentionally never closed (no CloseHandle): it must stay
    //   live until process exit so KILL_ON_JOB_CLOSE fires then. HANDLE has no Drop,
    //   so not closing it leaks nothing beyond that intended kernel object.
    unsafe {
        let job = CreateJobObjectW(null(), null());
        if job.is_null() || job == INVALID_HANDLE_VALUE {
            tracing::warn!("CreateJobObjectW failed — child processes will not be killed automatically on hard exit");
            return;
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 {
            tracing::warn!("SetInformationJobObject failed — child processes will not be killed automatically on hard exit");
            return;
        }

        let ok = AssignProcessToJobObject(job, GetCurrentProcess());
        if ok == 0 {
            tracing::warn!("AssignProcessToJobObject failed — child processes will not be killed automatically on hard exit");
            return;
        }

        // `HANDLE` is just a `*mut c_void` (no Drop), so going out of
        // scope does not call `CloseHandle`. The kernel object stays
        // live until process exit, which is exactly what we want — that
        // is when `KILL_ON_JOB_CLOSE` fires.
        let _ = job;
        tracing::debug!("bound process to Job Object with KILL_ON_JOB_CLOSE");
    }
}

#[cfg(not(windows))]
pub fn bind_child_processes_to_self() {
    // TODO: prctl(PR_SET_PDEATHSIG) on Linux, posix_spawn flags elsewhere.
    // Not currently a supported target.
}
