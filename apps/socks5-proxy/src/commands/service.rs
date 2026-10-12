//! Install and manage tor-socks5 as an OS service.
//!
//! The cross-platform install/uninstall/start/stop/status lifecycle is
//! delegated to the [`service_manager`] crate, which targets systemd,
//! OpenRC, launchd, the Windows SCM and the BSD `rc.d` system.
//!
//! On Linux/macOS/BSD the installed service simply runs the binary in
//! its normal foreground-server mode; the platform supervisor sends
//! `SIGTERM` to stop it, which our signal handler already treats as a
//! clean shutdown. Windows is the exception: a Windows service must talk
//! to the Service Control Manager, so the installed image path carries
//! the [`WINDOWS_SERVICE_RUN_ARG`] marker and the binary hands control to
//! the SCM dispatcher in [`windows_runtime`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};

/// Service identifier. Resolves to the systemd unit name `tor-socks5`,
/// the launchd label `tor-socks5`, and the Windows service name
/// `tor-socks5`.
const SERVICE_LABEL: &str = "tor-socks5";

/// Default config filename created/pinned at install time when no
/// explicit `--config` is given. Mirrors `config::DEFAULT_FILE`.
const DEFAULT_CONFIG_FILE: &str = "tor-socks5.ktav";

/// Marker argument injected into the installed Windows service image
/// path so the binary knows to enter the SCM dispatcher at startup.
#[cfg(windows)]
pub const WINDOWS_SERVICE_RUN_ARG: &str = "__run-windows-service";

#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    /// Register the service with the OS supervisor (pins the config path
    /// and enables start-on-boot).
    Install,
    /// Remove the service registration.
    Uninstall,
    /// Start the installed service.
    Start,
    /// Stop the running service.
    Stop,
    /// Print the current service status.
    Status,
}

fn label() -> ServiceLabel {
    ServiceLabel {
        qualifier: None,
        organization: None,
        application: SERVICE_LABEL.to_string(),
    }
}

fn manager(user: bool) -> Result<Box<dyn ServiceManager>> {
    let mut mgr = <dyn ServiceManager>::native().context("detecting the native service manager")?;
    if user {
        mgr.set_level(ServiceLevel::User)
            .context("this platform's service manager does not support user-level services")?;
    }
    Ok(mgr)
}

/// Entry point for the `service` subcommand.
pub fn run(action: ServiceAction, user: bool, config_override: Option<&Path>) -> Result<()> {
    let mgr = manager(user)?;
    match action {
        ServiceAction::Install => install(mgr.as_ref(), config_override),
        ServiceAction::Uninstall => {
            mgr.uninstall(ServiceUninstallCtx { label: label() })
                .context("uninstalling the service")?;
            println!("service \"{SERVICE_LABEL}\" uninstalled");
            Ok(())
        }
        ServiceAction::Start => {
            mgr.start(ServiceStartCtx { label: label() })
                .context("starting the service")?;
            println!("service \"{SERVICE_LABEL}\" started");
            Ok(())
        }
        ServiceAction::Stop => {
            mgr.stop(ServiceStopCtx { label: label() })
                .context("stopping the service")?;
            println!("service \"{SERVICE_LABEL}\" stopped");
            Ok(())
        }
        ServiceAction::Status => {
            let status = mgr
                .status(ServiceStatusCtx { label: label() })
                .context("querying the service status")?;
            println!("service \"{SERVICE_LABEL}\": {}", describe(&status));
            Ok(())
        }
    }
}

fn install(mgr: &dyn ServiceManager, config_override: Option<&Path>) -> Result<()> {
    let program = std::env::current_exe().context("resolving the current executable path")?;

    // A service has an unpredictable working directory, so always pin an
    // absolute config path into the service definition. Create a default
    // config there if none exists yet, so the service can actually start.
    let config_path = resolve_config_path(config_override)?;
    if !config_path.exists() {
        crate::config::Config::default()
            .write(&config_path)
            .with_context(|| format!("creating default config at {}", config_path.display()))?;
        println!("created default config at {}", config_path.display());
    }

    // `args` is only mutated on Windows (the SCM marker push below); on other
    // platforms that branch is compiled out, leaving the binding unmutated.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut args: Vec<OsString> = vec!["--config".into(), config_path.clone().into_os_string()];

    // On Windows the service process must enter the SCM dispatcher; the
    // marker arg trips that path at startup.
    #[cfg(windows)]
    args.push(WINDOWS_SERVICE_RUN_ARG.into());

    mgr.install(ServiceInstallCtx {
        label: label(),
        program,
        args,
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: Default::default(),
    })
    .context("installing the service")?;

    println!(
        "service \"{SERVICE_LABEL}\" installed (config: {})",
        config_path.display()
    );
    println!(
        "note: configure bridges or an upstream proxy before starting, or the service will exit."
    );
    Ok(())
}

/// Resolve the config path to pin into the service definition: the given
/// override, or `tor-socks5.ktav` in the current directory — made
/// absolute either way.
fn resolve_config_path(config_override: Option<&Path>) -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("resolving the current directory")?;
    let raw = match config_override {
        Some(p) => p.to_path_buf(),
        None => cwd.join(DEFAULT_CONFIG_FILE),
    };
    Ok(if raw.is_absolute() {
        raw
    } else {
        cwd.join(raw)
    })
}

fn describe(status: &ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::NotInstalled => "not installed",
        ServiceStatus::Running => "running",
        ServiceStatus::Stopped(_) => "stopped",
    }
}

/// Windows-only SCM runtime. When started by the Service Control Manager,
/// the binary re-enters here (via the [`WINDOWS_SERVICE_RUN_ARG`] marker)
/// and runs the proxy under SCM control, reporting status transitions and
/// shutting down on the Stop control.
#[cfg(windows)]
pub mod windows_runtime {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::SERVICE_LABEL;

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    /// Hand control to the SCM dispatcher. Blocks until the service stops.
    pub fn dispatch() -> anyhow::Result<()> {
        service_dispatcher::start(SERVICE_LABEL, ffi_service_main)
            .map_err(|e| anyhow::anyhow!("windows service dispatcher failed: {e}"))
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        // The SCM gives us no console; errors can only be surfaced via the
        // reported exit code (and, once configured, the proxy's own log).
        let _ = run_service();
    }

    fn run_service() -> windows_service::Result<()> {
        let notify = Arc::new(tokio::sync::Notify::new());
        let handler_notify = Arc::clone(&notify);
        let event_handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                handler_notify.notify_one();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_LABEL, event_handler)?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let exit_code = run_proxy(Arc::clone(&notify));

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }

    /// Build a Tokio runtime and run the proxy until the SCM Stop event
    /// fires `notify`. Returns a Win32 exit code (0 = clean).
    fn run_proxy(notify: Arc<tokio::sync::Notify>) -> u32 {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return 1,
        };

        let shutdown = async move {
            notify.notified().await;
        };
        let result = runtime.block_on(crate::server::run_server(
            crate::server::ServerArgs {
                config_override: config_from_image_args(),
                upstream_addr: None,
                upstream_user: None,
                upstream_pass: None,
                no_upstream: false,
            },
            shutdown,
        ));
        match result {
            Ok(()) => 0,
            Err(_) => 1,
        }
    }

    /// Recover the `--config <path>` pinned into the installed image path.
    fn config_from_image_args() -> Option<PathBuf> {
        let mut it = std::env::args_os();
        while let Some(arg) = it.next() {
            if arg.to_str() == Some("--config") {
                return it.next().map(PathBuf::from);
            }
        }
        None
    }
}
