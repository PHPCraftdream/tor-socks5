use super::*;

use std::{
    ffi::OsString,
    fmt,
    io::{self, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

static LOGGING_TEST_LOCK: Mutex<()> = Mutex::new(());

fn emit_owned_event(message: &'static str) {
    tracing::info!(target: "owned_logging", "{message}");
}

fn emit_owned_log(message: &'static str) {
    log::info!(target: "owned_logging", "{message}");
}

fn emit_owned_debug(message: &'static str) {
    tracing::debug!(target: "owned_logging", "{message}");
}

fn emit_owned_trace(message: &'static str) {
    tracing::trace!(target: "owned_logging", "{message}");
}

fn emit_owned_new_trace(message: &'static str) {
    tracing::trace!(target: "owned_logging", "new={message}");
}

fn owned_span(role: &str) -> tracing::Span {
    tracing::info_span!(target: "owned_logging", "owned_span", role)
}

struct OwnedDebugRole(&'static str);

impl fmt::Debug for OwnedDebugRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

fn owned_debug_span(role: &'static str) -> tracing::Span {
    tracing::info_span!(
        target: "owned_logging",
        "owned_debug_span",
        role = tracing::field::debug(OwnedDebugRole(role))
    )
}

#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture_events(filter: tracing_subscriber::EnvFilter, emit: impl FnOnce()) -> String {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&output);
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || CaptureWriter(Arc::clone(&writer_output)))
            .with_filter(filter),
    );
    tracing::subscriber::with_default(subscriber, emit);
    let bytes = output.lock().expect("capture lock").clone();
    String::from_utf8(bytes).expect("UTF-8 logs")
}

struct RustLogGuard(Option<OsString>);

impl RustLogGuard {
    fn set(value: Option<&str>) -> Self {
        let previous = std::env::var_os("RUST_LOG");
        match value {
            Some(value) => std::env::set_var("RUST_LOG", value),
            None => std::env::remove_var("RUST_LOG"),
        }
        Self(previous)
    }
}

impl Drop for RustLogGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => std::env::set_var("RUST_LOG", value),
            None => std::env::remove_var("RUST_LOG"),
        }
    }
}

#[test]
fn logging_filters_levels_targets_and_rust_log_override() {
    let _lock = LOGGING_TEST_LOCK.lock().expect("logging test lock");
    let default_env = RustLogGuard::set(None);
    let error_output = capture_events(default_log_filter(Level::ERROR), || {
        tracing::error!(target: "ordinary", "error-visible");
        tracing::warn!(target: "ordinary", "warn-hidden");
        tracing::info!(target: "fast_socks5", "info-hidden");
    });
    assert!(error_output.contains("error-visible"));
    assert!(!error_output.contains("warn-hidden"));
    assert!(!error_output.contains("info-hidden"));

    let debug_output = capture_events(default_log_filter(Level::DEBUG), || {
        tracing::debug!(target: "ordinary", "debug-visible");
        tracing::info!(target: "fast_socks5", "info-visible");
    });
    assert!(debug_output.contains("debug-visible"));
    assert!(debug_output.contains("info-visible"));

    drop(default_env);
    let _override_env = RustLogGuard::set(Some("error,fast_socks5=debug"));
    let override_output = capture_events(default_log_filter(Level::ERROR), || {
        tracing::debug!(target: "fast_socks5", "target-override-visible");
        tracing::debug!(target: "ordinary", "ordinary-debug-hidden");
    });
    assert!(override_output.contains("target-override-visible"));
    assert!(!override_output.contains("ordinary-debug-hidden"));
}

#[test]
fn logging_guard_preserves_host_and_does_not_truncate_file() {
    let _lock = LOGGING_TEST_LOCK.lock().expect("logging test lock");
    assert!(!has_logging_subscriber());
    let host_output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&host_output);
    let host = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || CaptureWriter(Arc::clone(&writer_output))),
    );
    tracing::subscriber::set_global_default(host).expect("install host subscriber");

    let statedir = std::env::temp_dir().join(format!("lyrebird-logging-{}", std::process::id()));
    std::fs::create_dir_all(&statedir).expect("create logging test directory");
    let log_path = statedir.join("obfs4proxy.log");
    std::fs::write(&log_path, b"sentinel\n").expect("seed log file");
    let unrelated_state_dir = statedir.join("unrelated-missing-directory");

    let guard = init_logging_recvr(
        true,
        false,
        "ERROR",
        unrelated_state_dir
            .to_str()
            .expect("state directory is UTF-8"),
    )
    .expect("host subscriber should be preserved");
    tracing::error!("host-event");
    assert_eq!(
        std::fs::read(&log_path).expect("read log file"),
        b"sentinel\n"
    );
    assert!(
        String::from_utf8(host_output.lock().expect("capture lock").clone())
            .expect("UTF-8 logs")
            .contains("host-event")
    );
    assert_eq!(format!("{}", sensitive("secret")), "secret");
    drop(guard);
    assert_eq!(format!("{}", sensitive("secret")), "[scrubbed]");

    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        let guard = init_logging_recvr(false, true, "ERROR", statedir.to_str().unwrap())
            .expect("an explicitly disabled subscriber must be preserved");
        assert_eq!(format!("{}", sensitive("secret")), "[scrubbed]");
        drop(guard);
    });

    let safe_guard = safelog::enforce_safe_logging().expect("safe guard");
    let incompatible = init_logging_recvr(
        false,
        false,
        "ERROR",
        statedir.to_str().expect("state directory is UTF-8"),
    );
    assert!(incompatible.is_err(), "incompatible safelog mode must fail");
    drop(safe_guard);
    std::fs::remove_dir_all(statedir).expect("remove logging test directory");
}

#[test]
fn owned_logging_reconfigures_transactionally_in_subprocess() {
    const CHILD: &str = "LYREBIRD_OWNED_LOGGING_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let statedir =
            std::env::temp_dir().join(format!("lyrebird-owned-logging-{}", std::process::id()));
        std::fs::create_dir_all(&statedir).expect("create logging directory");
        let reconfigured_dir = statedir.join("reconfigured");
        std::fs::create_dir_all(&reconfigured_dir).expect("create reconfigured directory");
        std::env::set_var(
            "RUST_LOG",
            "owned_logging=info,owned_logging[owned_span{role=allowed}]=trace,owned_logging[owned_debug_span{role=^ALLOWED$}]=trace",
        );
        let guard = init_logging_recvr(
            true,
            false,
            "ERROR",
            statedir.to_str().expect("UTF-8 temp path"),
        )
        .expect("install owned subscriber");
        let allowed = owned_span("allowed");
        let _allowed_guard = allowed.enter();
        emit_owned_debug("first-file-event");
        emit_owned_debug("field-event-allowed");
        emit_owned_trace("field-trace-allowed");
        emit_owned_log("first-log-event");
        drop(_allowed_guard);
        let denied = owned_span("denied");
        let _denied_guard = denied.enter();
        emit_owned_debug("field-event-denied");
        emit_owned_trace("field-trace-denied");
        drop(_denied_guard);

        let reentered = owned_span("allowed");
        let debug_reentered = owned_debug_span("ALLOWED");
        std::env::remove_var("RUST_LOG");
        let missing_dir = statedir.join("missing");
        assert!(init_logging_recvr(
            true,
            false,
            "INFO",
            missing_dir.to_str().expect("UTF-8 temp path"),
        )
        .is_err());
        emit_owned_event("event-after-failed-reconfigure");

        let active = owned_span("allowed");
        let active_guard = active.enter();
        emit_owned_debug("same-span-before-reconfigure");
        let migrated = init_logging_recvr(
            true,
            false,
            "ERROR",
            reconfigured_dir.to_str().expect("UTF-8 temp path"),
        )
        .expect("change destination with active span");
        emit_owned_debug("same-span-after-reconfigure");
        emit_owned_new_trace("new-callsite-inside-old-span");
        drop(migrated);

        std::env::set_var(
            "RUST_LOG",
            "owned_logging=info,owned_logging[owned_span{role=allowed}]=trace,owned_logging[owned_debug_span{role=^ALLOWED$}]=trace",
        );
        let relaxed = init_logging_recvr(
            true,
            false,
            "DEBUG",
            reconfigured_dir.to_str().expect("UTF-8 temp path"),
        )
        .expect("relax logging with active span");
        emit_owned_debug("same-span-after-relax");
        emit_owned_trace("field-trace-allowed-after-relax");
        drop(relaxed);
        drop(active_guard);
        reentered.in_scope(|| emit_owned_trace("reentered-after-relax"));
        debug_reentered.in_scope(|| emit_owned_trace("debug-field-after-relax"));
        owned_span("denied").in_scope(|| emit_owned_trace("field-trace-denied-after-relax"));

        let no_file = init_logging_recvr(
            false,
            false,
            "ERROR",
            reconfigured_dir.to_str().expect("UTF-8 temp path"),
        )
        .expect("disable file logging");
        emit_owned_event("event-after-file-disabled");
        emit_owned_log("event-after-file-disabled-log");
        drop(no_file);
        std::env::set_var(
            "RUST_LOG",
            "owned_logging=info,owned_logging[owned_span{role=allowed}]=trace",
        );
        let reenabled = init_logging_recvr(
            true,
            false,
            "DEBUG",
            reconfigured_dir.to_str().expect("UTF-8 temp path"),
        )
        .expect("re-enable file logging");
        emit_owned_event("event-after-file-reenabled");
        emit_owned_log("event-after-file-reenabled-log");
        owned_span("allowed").in_scope(|| emit_owned_trace("new-span-after-reconfigure"));
        owned_span("denied").in_scope(|| emit_owned_trace("denied-span-after-reconfigure"));
        drop(reenabled);
        drop(guard);

        let output =
            std::fs::read_to_string(statedir.join("obfs4proxy.log")).expect("read owned log");
        let reconfigured_output = std::fs::read_to_string(reconfigured_dir.join("obfs4proxy.log"))
            .expect("read reconfigured log");
        assert!(output.contains("first-file-event"));
        assert!(output.contains("field-event-allowed"));
        assert!(!output.contains("field-event-denied"));
        assert!(output.contains("field-trace-allowed"));
        assert!(!output.contains("field-trace-denied"));
        assert!(output.contains("first-log-event"));
        assert!(output.contains("event-after-failed-reconfigure"));
        assert!(!output.contains("same-span-after-reconfigure"));
        assert!(!output.contains("new-callsite-inside-old-span"));
        assert!(!reconfigured_output.contains("same-span-after-reconfigure"));
        assert!(!reconfigured_output.contains("new-callsite-inside-old-span"));
        assert!(reconfigured_output.contains("same-span-after-relax"));
        assert!(reconfigured_output.contains("field-trace-allowed-after-relax"));
        assert!(!reconfigured_output.contains("field-trace-denied-after-relax"));
        assert!(reconfigured_output.contains("reentered-after-relax"));
        assert!(reconfigured_output.contains("debug-field-after-relax"));
        assert!(reconfigured_output.contains("event-after-file-reenabled"));
        assert!(reconfigured_output.contains("event-after-file-reenabled-log"));
        assert!(reconfigured_output.contains("new-span-after-reconfigure"));
        assert!(!reconfigured_output.contains("denied-span-after-reconfigure"));
        assert!(!reconfigured_output.contains("event-after-file-disabled"));
        assert!(!reconfigured_output.contains("event-after-file-disabled-log"));
        println!("LYREBIRD_OWNED_LOGGING_CHILD_RAN");
        let _ = std::fs::remove_dir_all(statedir);
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "logging_tests::owned_logging_reconfigures_transactionally_in_subprocess",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::null())
        .output()
        .expect("run logging subprocess");
    assert!(
        output.status.success(),
        "owned logging subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("LYREBIRD_OWNED_LOGGING_CHILD_RAN"));
}

#[test]
fn owned_logging_bridges_log_events_in_subprocess() {
    const CHILD: &str = "LYREBIRD_LOG_BRIDGE_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::env::remove_var("RUST_LOG");
        let statedir =
            std::env::temp_dir().join(format!("lyrebird-log-bridge-{}", std::process::id()));
        std::fs::create_dir_all(&statedir).expect("create logging directory");
        let guard = init_logging_recvr(
            true,
            false,
            "INFO",
            statedir.to_str().expect("UTF-8 temp path"),
        )
        .expect("install owned subscriber");
        log::info!(target: "owned_logging", "standalone-log-event");
        drop(guard);
        let output =
            std::fs::read_to_string(statedir.join("obfs4proxy.log")).expect("read owned log");
        assert!(output.contains("standalone-log-event"));
        println!("LYREBIRD_LOG_BRIDGE_CHILD_RAN");
        let _ = std::fs::remove_dir_all(statedir);
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "logging_tests::owned_logging_bridges_log_events_in_subprocess",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::null())
        .output()
        .expect("run log bridge subprocess");
    assert!(
        output.status.success(),
        "log bridge subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("LYREBIRD_LOG_BRIDGE_CHILD_RAN"));
}

#[test]
fn external_log_logger_is_preserved_in_subprocess() {
    const CHILD: &str = "LYREBIRD_EXTERNAL_LOGGER_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::env::remove_var("RUST_LOG");
        struct NoopLogger;
        impl log::Log for NoopLogger {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                false
            }

            fn log(&self, _: &log::Record<'_>) {}

            fn flush(&self) {}
        }
        static LOGGER: NoopLogger = NoopLogger;
        log::set_logger(&LOGGER).expect("install external logger");
        log::set_max_level(log::LevelFilter::Warn);
        let before = log::max_level();
        let statedir =
            std::env::temp_dir().join(format!("lyrebird-external-logger-{}", std::process::id()));
        std::fs::create_dir_all(&statedir).expect("create logging directory");
        let guard = init_logging_recvr(
            false,
            false,
            "DEBUG",
            statedir.to_str().expect("UTF-8 temp path"),
        )
        .expect("preserve external logger");
        assert_eq!(log::max_level(), before);
        let reconfigured = init_logging_recvr(
            false,
            false,
            "TRACE",
            statedir.to_str().expect("UTF-8 temp path"),
        )
        .expect("reconfigure with external logger");
        assert_eq!(log::max_level(), before);
        drop(reconfigured);
        drop(guard);
        let _ = std::fs::remove_dir_all(statedir);
        println!("LYREBIRD_EXTERNAL_LOGGER_CHILD_RAN");
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "logging_tests::external_log_logger_is_preserved_in_subprocess",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::null())
        .output()
        .expect("run external logger subprocess");
    assert!(
        output.status.success(),
        "external logger subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("LYREBIRD_EXTERNAL_LOGGER_CHILD_RAN"));
}
