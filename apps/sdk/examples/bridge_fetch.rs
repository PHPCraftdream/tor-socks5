use std::error::Error;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::time::Duration;

use tor_socks5::config::Config;
use tor_socks5::runtime::{fetch_bridges, FetchBridgesParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
        Some(&config_path),
        FetchBridgesParams {
            timeout: Duration::from_secs(60),
            count: 3,
            probe: false,
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
