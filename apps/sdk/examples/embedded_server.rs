//! Minimal embedded-server example. The configured upstream SOCKS5 proxy must
//! be reachable for client connections; server startup itself does not
//! connect to it or bootstrap Tor.

use tor_socks5::config::Config;
use tor_socks5::server::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
        listen: vec!["127.0.0.1:0".into()],
        ..Config::default()
    };

    let server = Server::builder(config)
        .upstream(Some("127.0.0.1:9050".into()), None, None)
        .start()
        .await?;
    tokio::signal::ctrl_c().await?;
    server.shutdown().await?;
    Ok(())
}
