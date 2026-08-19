//! Pluggable-transport helper binary for arti on Android.
//!
//! On Android, the tor-socks5 engine is a dlopen'ed cdylib (libtorsocks5.so)
//! with no meaningful `current_exe()`. Arti needs a separate small executable
//! it can spawn as the managed pluggable-transport (PT) child process — this
//! crate is that executable. When arti sets `TOR_PT_MANAGED_TRANSPORT_VER`,
//! we enter PT mode and run the lyrebird loop.

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    // Busybox-style dispatch: when arti spawns us as a managed pluggable
    // transport, it sets `TOR_PT_MANAGED_TRANSPORT_VER`. In that case we
    // run the lyrebird PT loop. If the env var is not set, this binary was
    // invoked directly (not by arti) — we fail fast with a clear error.
    if std::env::var_os("TOR_PT_MANAGED_TRANSPORT_VER").is_some() {
        // arti (tor-ptmgr) sets TOR_PT_EXIT_ON_STDIN_CLOSE=1 on managed PT
        // children and, per the pluggable-transport spec, signals shutdown by
        // closing the child's stdin. `ptrs-gesher-lyrebird` 0.5.2+ honours
        // this itself (fixed upstream: the process now watches stdin and
        // exits cleanly on EOF when the env var is set) — no workaround
        // needed here.
        let rt = tokio::runtime::Builder::new_multi_thread()
            // A bursty client (e.g. Telegram opening dozens of simultaneous
            // connections) drives just as many concurrent obfs4/webtunnel
            // handshake attempts here, in the PT child. A small pool risks
            // worker-starvation that would stall bridge connections.
            .worker_threads(32)
            .enable_all()
            .build()
            .context("building Tokio runtime for pluggable-transport mode")?;
        return rt.block_on(lyrebird::run());
    }

    anyhow::bail!(
        "this is a pluggable-transport helper exec'd by arti, not meant to be run directly"
    );
}
