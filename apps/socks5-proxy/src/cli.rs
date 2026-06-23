//! Command-line interface definition (clap derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::service::ServiceAction;
use crate::users_cli::UsersAction;

#[derive(Parser)]
#[command(
    name = "tor-socks5",
    bin_name = "tor-socks5",
    version,
    disable_help_subcommand = true,
    about = "A local SOCKS5 proxy that tunnels TCP through Tor and fetches/probes its own bridges.",
    long_about = "tor-socks5 is a local SOCKS5 (RFC 1928) proxy. By default it bootstraps an \
embedded Tor client (arti) over pluggable-transport bridges (obfs4 / webtunnel) and forwards \
every CONNECT through the Tor network.\n\n\
It manages its own bridges: configured bridges are probed for reachability at startup (dead \
ones are skipped, live ones sorted fastest-first and cached), and `bridges fetch` pulls fresh \
bridges from public collectors over Tor and merges the working ones into the config.\n\n\
Optional extras: RFC 1929 username/password auth for SOCKS5 clients (with trust-on-first-use \
provisioning), routing egress through an upstream SOCKS5 proxy instead of Tor, and installation \
as an OS service (systemd / launchd / Windows SCM / rc.d).\n\n\
With no subcommand, the proxy server runs. Configuration is read from a Ktav file \
(default `tor-socks5.ktav` in the current directory, or `$TOR_SOCKS5_CONFIG`); a template is \
created on first run.",
    after_help = "EXAMPLES:\n  \
tor-socks5                              # run the proxy (creates tor-socks5.ktav on first run)\n  \
tor-socks5 --config /etc/tor-socks5.ktav\n  \
tor-socks5 users add alice              # add a SOCKS5 user (prompts for a password)\n  \
tor-socks5 users add --init alice       # add a user whose first login sets the password\n  \
tor-socks5 users add --allow-onion bob  # add a user permitted to reach .onion services\n  \
tor-socks5 users allow-onion alice      # grant .onion access to an existing user\n  \
tor-socks5 bridges fetch                # fetch & merge fresh bridges over Tor\n  \
tor-socks5 --upstream 127.0.0.1:9050    # egress via an upstream SOCKS5 instead of Tor\n  \
tor-socks5 service install              # install as a system service\n  \
tor-socks5 --daemon --pid-file /run/tor-socks5.pid   # run in the background (Unix only)\n  \
tor-socks5 help --all                   # print the full bundled documentation\n\n\
Run `tor-socks5 <command> --help` for command-specific options, or \
`tor-socks5 help` to browse the bundled manuals."
)]
pub(crate) struct Cli {
    /// Override the main-config path used to resolve auxiliary files.
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,

    /// Route egress through this upstream SOCKS5 proxy (`host:port`)
    /// instead of Tor. Enables the upstream and overrides the config.
    #[arg(long, value_name = "HOST:PORT")]
    pub(crate) upstream: Option<String>,

    /// Username for the upstream proxy (RFC 1929). Overrides the config.
    #[arg(long)]
    pub(crate) upstream_user: Option<String>,

    /// Password for the upstream proxy (RFC 1929). Overrides the config.
    #[arg(long)]
    pub(crate) upstream_pass: Option<String>,

    /// Force-disable the upstream proxy even if enabled in the config
    /// (falls back to the Tor egress).
    #[arg(long)]
    pub(crate) no_upstream: bool,

    /// Run in the background as a daemon (Unix only): detach from the
    /// controlling terminal, redirect stdio to /dev/null. On Windows,
    /// install as a service instead (`tor-socks5 service install`).
    #[arg(long, short = 'd')]
    pub(crate) daemon: bool,

    /// Path to write the daemon's PID file (Unix only; used with --daemon).
    #[arg(long, value_name = "PATH")]
    pub(crate) pid_file: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Manage user accounts for SOCKS5 authentication.
    Users {
        #[command(subcommand)]
        action: UsersAction,
    },
    /// Fetch and manage bridges.
    Bridges {
        #[command(subcommand)]
        action: BridgesAction,
    },
    /// Install/manage tor-socks5 as an OS service (systemd, launchd,
    /// Windows SCM, rc.d).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
        /// Operate on a per-user service instead of a system-wide one
        /// (systemd `--user`, launchd LaunchAgent). Not all platforms
        /// support this.
        #[arg(long)]
        user: bool,
    },
    /// Print the bundled documentation (the `docs/` manuals, embedded in
    /// the binary). With no arguments it lists the topics; `--all` prints
    /// every topic; pass a topic name (e.g. `bridges`) for just that one.
    Help {
        /// Print every documentation topic, end to end.
        #[arg(long)]
        all: bool,
        /// A specific topic to print (e.g. `bridges`, `auth`, `webtunnel`).
        topic: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum BridgesAction {
    /// Fetch new bridges from configured HTTPS sources via Tor,
    /// probe them, and merge the live ones into the config.
    Fetch {
        /// Print the merge plan without writing the config.
        #[arg(long)]
        dry_run: bool,
        /// Skip bridge reachability probing.
        #[arg(long)]
        no_probe: bool,
        /// Per-source HTTPS fetch timeout in seconds.
        #[arg(long, default_value = "30")]
        timeout_secs: u64,
        /// Stop after collecting this many reachable new bridges. Probing
        /// is lazy (one bridge at a time, no concurrent burst), so a large
        /// fetched list is never hammered all at once. Ignored with
        /// `--no-probe`.
        #[arg(long, default_value = "10")]
        count: usize,
    },
}
