//! Process-level initialisation kept out of the server tree: logging,
//! crypto provider, child-process binding, environment and signals.

#[path = "children.rs"]
mod children;
#[path = "logging.rs"]
mod logging;
#[path = "run.rs"]
mod run;
#[path = "signals.rs"]
mod signals;

pub(crate) use logging::{init_tracing, install_crypto_provider};
pub(crate) use run::run_server_process;
pub(crate) use signals::wait_for_signal;
