use std::error::Error;
use std::path::PathBuf;

use tor_socks5::config::Config;
use tor_socks5::onion::host::{OnionHost, OnionHostConfig};
use tor_socks5::runtime::{build_tor_settings_with_pt, PtBinary, TorHandle};
use tor_socks5::tor::TorTunnel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let config_path = PathBuf::from(
        args.next()
            .ok_or("usage: onion_host CONFIG_PATH PT_BINARY")?,
    );
    let pt = PtBinary::Explicit(PathBuf::from(
        args.next()
            .ok_or("usage: onion_host CONFIG_PATH PT_BINARY")?,
    ));
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }

    let config = Config::load_with_override(Some(&config_path))?.into_config();
    run(config, config_path, pt).await
}

async fn run(config: Config, config_path: PathBuf, pt: PtBinary) -> Result<(), Box<dyn Error>> {
    let settings = build_tor_settings_with_pt(&config, Some(&config_path), pt).await?;
    let tunnel = TorTunnel::bootstrap_with(settings.clone()).await?;
    let handle = TorHandle::new_with_settings(tunnel, &settings);
    let host_config = OnionHostConfig::new(
        handle.clone(),
        tor_socks5::runtime::arti_keystore_dir(Some(&config_path)),
        Default::default(),
    )
    .with_entries(config.onion_services)
    .with_config_path(Some(config_path));
    let host = OnionHost::new(host_config).start();

    let signal = tokio::signal::ctrl_c().await;
    host.shutdown().await;
    drop(handle.drain().await);
    signal?;
    Ok(())
}
