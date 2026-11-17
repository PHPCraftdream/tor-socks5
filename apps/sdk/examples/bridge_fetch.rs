use std::error::Error;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::time::Duration;

use tor_socks5::config::Config;
use tor_socks5::runtime::{fetch_bridges, FetchBridgesParams, PtBinary};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Host-process initialisation (R1): the host installs the crypto provider
    // and sets up its own log subscriber; the SDK never does this on its own.
    tor_socks5::install_crypto_provider();
    let log = tor_socks5::config::LogConfig {
        default: "info".to_owned(),
        targets: Default::default(),
        ..Default::default()
    };
    let (log_layer, _guard) = tor_socks5::runtime::log_layer(&log);
    tracing_subscriber::registry().with(log_layer).init();
    let mut args = std::env::args_os().skip(1);
    let config_path = args.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidInput, "usage: bridge_fetch CONFIG_PATH")
    })?;
    if args.next().is_some() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "unexpected argument").into());
    }

    let config = Config::load_with_override(Some(&config_path))?.into_config();
    let outcome = fetch_bridges(
        &config,
        &config_path,
        FetchBridgesParams {
            timeout: Duration::from_secs(60),
            count: 3,
            probe: false,
            // A host that cannot be re-spawned as a PT dispatcher must pass
            // `PtBinary::Explicit` instead (see the runtime `pt` docs).
            pt_binary: PtBinary::Environment,
            cancel: Default::default(),
        },
    )
    .await?;

    println!(
        "added={} promoted={:?} pool_len={}",
        outcome.added, outcome.promoted, outcome.pool_len
    );
    Ok(())
}
