//! Minimal embedded-server example. A config path is required (H13): sibling
//! files (users registry, bridge store, DNS cache) are resolved from it, and
//! nothing is written to the current directory. The configured upstream SOCKS5
//! proxy must be reachable for client connections; server startup itself does
//! not connect to it or bootstrap Tor.

use std::path::PathBuf;

use tor_socks5::config::Config;
use tor_socks5::server::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("usage: embedded_server <CONFIG_PATH>")?,
    );
    let config = Config {
        listen: vec!["127.0.0.1:0".into()],
        ..Config::default()
    };

    let mut signal_error = None;
    let shutdown = async {
        signal_error = tokio::signal::ctrl_c().await.err();
    };
    let result = Server::builder(config)
        .config_path(config_path)
        .upstream(Some("127.0.0.1:9050".into()), None, None)
        .run_until(shutdown)
        .await;
    result?;
    if let Some(error) = signal_error {
        return Err(error.into());
    }
    Ok(())
}
