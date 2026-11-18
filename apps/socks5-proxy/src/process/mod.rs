//! Process-level initialisation kept out of the server tree: logging,
//! crypto provider, child-process binding, environment and signals.

#[path = "logging.rs"]
mod logging;
#[path = "run.rs"]
mod run;
#[path = "signals.rs"]
mod signals;

pub(crate) use logging::init_tracing;
// The crypto provider and child-process binding now live in the runtime
// crate (`host` module); re-exported here so callers need not know.
pub(crate) use run::run_server_process;
pub(crate) use signals::wait_for_signal;
pub(crate) use tor_socks5::install_crypto_provider;
