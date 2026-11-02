//! Thin binary wrapper: delegates everything to `lyrebird::run()`. The
//! interesting code lives in `lib.rs` so `socks5-proxy` can dispatch into
//! it in-process when our own binary is spawned as a managed PT.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    lyrebird::run().await
}
