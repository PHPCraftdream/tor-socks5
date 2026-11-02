//! Process-level regression test for the `TOR_PT_EXIT_ON_STDIN_CLOSE`
//! behavior wired into `lyrebird::run()`.
//!
//! Each test launches the real `lyrebird` binary as a managed PT client
//! (the same shape of process arti's `tor-ptmgr` spawns), then either
//! does or does not close its stdin, and asserts on the resulting process
//! lifetime. This is the level at which the bug originally surfaced
//! downstream in `tor-socks5` — stale PT-child zombies accumulating
//! because the child ignored stdin close.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Build the `TOR_PT_*` environment a Tor parent (arti/tor) presents to
/// a PT-client child. Just enough for `lyrebird::run()` to print
/// `VERSION` / `CMETHOD …` / `CMETHODS DONE` and reach its accept loop.
///
/// We deliberately do NOT `env_clear()` the child's environment: a real
/// Tor PT parent (arti's `tor-ptmgr`, tor) only sets the `TOR_PT_*` vars
/// on top of the environment it inherited — it does not scrub
/// process-global vars like `SystemRoot` (Windows) / `LANG` (Unix) that
/// system libraries depend on. Tests that nuke the whole environment
/// fail on Windows for reasons unrelated to the behavior under test.
fn set_pt_client_env(cmd: &mut Command, state_dir: &std::path::Path) {
    cmd.env("TOR_PT_MANAGED_TRANSPORT_VER", "1");
    cmd.env("TOR_PT_CLIENT_TRANSPORTS", "obfs4");
    cmd.env("TOR_PT_STATE_LOCATION", state_dir);
}

/// A throwaway state dir under the system temp, unique per test invocation
/// so parallel runs don't collide.
fn fresh_state_dir(label: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "ptrs-gesher-lyrebird-stdin-test-{}-{label}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create state dir");
    p
}

/// Poll `child` until it exits or `deadline` elapses. Returns `Ok(status)`
/// on exit, `Err(())` if still running at the deadline.
fn wait_with_timeout(
    child: &mut std::process::Child,
    deadline: Duration,
) -> Result<std::process::ExitStatus, ()> {
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait on child") {
            Some(s) => return Ok(s),
            None => {
                if start.elapsed() > deadline {
                    return Err(());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

#[test]
fn exits_promptly_on_stdin_close_when_exit_on_stdin_close_set() {
    let state_dir = fresh_state_dir("positive");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lyrebird"));
    set_pt_client_env(&mut cmd, &state_dir);
    cmd.env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1");
    // stdout is the PT-spec parent control channel (VERSION/CMETHOD/...);
    // we don't need to read it. stderr carries tracing logs. Null both so
    // a pipe-buffer fill can't deadlock the child against an unread pipe.
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().expect("spawn lyrebird");
    // Drop our stdin handle → the child observes EOF on its stdin.
    drop(child.stdin.take());

    let status = wait_with_timeout(&mut child, Duration::from_secs(5)).unwrap_or_else(|_| {
        let _ = child.kill();
        panic!(
            "lyrebird did not exit within 5s of stdin close despite \
             TOR_PT_EXIT_ON_STDIN_CLOSE=1 — the watcher is not wired in"
        );
    });

    assert!(
        status.success(),
        "lyrebird should exit cleanly (code 0) on stdin close, got {status}"
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn does_not_exit_on_stdin_close_when_exit_on_stdin_close_unset() {
    let state_dir = fresh_state_dir("negative");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lyrebird"));
    set_pt_client_env(&mut cmd, &state_dir);
    // TOR_PT_EXIT_ON_STDIN_CLOSE intentionally NOT set; explicitly remove
    // it in case the ambient test environment happens to carry it.
    cmd.env_remove("TOR_PT_EXIT_ON_STDIN_CLOSE");
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().expect("spawn lyrebird");
    // Give the child a moment to finish its PT handshake (VERSION /
    // CMETHOD / CMETHODS DONE) and enter the select! accept loop before
    // we close stdin. Without this, a child that hasn't yet reached the
    // loop could exit for unrelated reasons and confuse the assertion.
    std::thread::sleep(Duration::from_millis(750));
    drop(child.stdin.take());

    // Watch for an exit. We do NOT want one — the old "ignore stdin"
    // behavior is what's correct here. 1.5s is well within the 5s the
    // positive case takes, but long enough to distinguish "exited" from
    // "still in its accept loop".
    let exited = wait_with_timeout(&mut child, Duration::from_millis(1500));
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        exited.is_err(),
        "lyrebird must still be running 1.5s after stdin close when \
         TOR_PT_EXIT_ON_STDIN_CLOSE is not set — closing stdin should \
         be a no-op in that mode"
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}
