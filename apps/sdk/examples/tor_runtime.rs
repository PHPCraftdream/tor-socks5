use std::error::Error;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use tor_socks5::config::Config;
use tor_socks5::runtime::{
    build_tor_settings_with_pt, close_global, init_global, launch_producers, observation_layer,
    CancellationToken, ObservationSink, PtBinary, TorHandle,
};
use tor_socks5::tor::TorTunnel;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Host-process initialisation (R1): the host installs the crypto provider
    // and composes its own log subscriber; the SDK never does this on its own.
    tor_socks5::install_crypto_provider();
    let log = tor_socks5::config::LogConfig {
        default: "info".to_owned(),
        targets: Default::default(),
        ..Default::default()
    };
    let (log_layer, _guard) = tor_socks5::runtime::log_layer(&log);
    let mut args = std::env::args_os().skip(1);
    let config_path = required(&mut args, "CONFIG_PATH")?;
    let pt_path = required(&mut args, "PT_BINARY")?;
    if args.next().is_some() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "unexpected argument").into());
    }

    let config = Config::load_with_override(Some(&config_path))?.into_config();
    let observations = ObservationSink::new();
    tracing_subscriber::registry()
        .with(log_layer)
        .with(observation_layer(&observations))
        .try_init()?;

    // This is the explicit network-start boundary: settings may probe bridges;
    // PT_BINARY must dispatch PT mode when configured bridges need it.
    let pt_binary = PtBinary::Explicit(pt_path);
    let settings =
        build_tor_settings_with_pt(&config, Some(&config_path), pt_binary.clone()).await?;
    let tunnel = TorTunnel::bootstrap_with(settings.clone()).await?;
    let handle = TorHandle::new_with_settings(tunnel, &settings);
    let _writer = init_global(Some(&config_path));
    let token = CancellationToken::new();
    let mut producers: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    launch_producers(
        handle.clone(),
        Some(config_path.clone()),
        &config,
        observations.clone(),
        settings.clone(),
        pt_binary.clone(),
        token.clone(),
        &mut producers,
    );

    let signal_result = tokio::signal::ctrl_c().await;
    token.cancel();
    for producer in producers {
        let _ = producer.await;
    }
    let store_result = close_global().await;
    drop(handle.drain().await);

    signal_result?;
    if let Some(result) = store_result {
        result?;
    }
    Ok(())
}

fn required(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> io::Result<PathBuf> {
    args.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("usage: tor_runtime CONFIG_PATH PT_BINARY (missing {name})"),
        )
    })
}
