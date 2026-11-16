//! The server module tree of the socks5-proxy binary, moved verbatim into
//! this crate (SDK-10, part 2; docs/plans/sdk-coverage-plan.md). The public
//! API step (builder, handle, typed errors) is SDK-11; until then only what
//! the binary itself consumes is `#[doc(hidden)] pub` — `run_server` /
//! `ServerArgs` (the process layer drives them) and `route`'s pool
//! validation used by the `bridges` CLI. Everything else stays crate-private.
//!
//! Behavior is unchanged: the same start/stop choreography, the same log
//! lines and the same exit codes. Only the log *target* moved: events that
//! used to carry the `socks5_proxy::server` target now carry
//! `tor_socks5_server::...` (see `proxy-config`'s `PRODUCT_TARGETS`, which
//! keeps the default `tor_=warn` filter from silencing them).
//!
//! The `test-seams` feature (dev-only, R10) mirrors the runtime crate's:
//! consumers' dev-dependencies may enable it to drive the server's seams
//! cross-crate. It must never be enabled in default/full builds.

mod config;

#[path = "server/dns_wiring.rs"]
mod dns_wiring;

/// Onion-service hosting shell (`spawn_services`), behind the
/// `onion-service` feature; a build without it only warns at startup.
mod onion;

#[doc(hidden)]
#[path = "server/egress/route.rs"]
pub mod route;

#[doc(hidden)]
#[path = "server/server.rs"]
pub mod server;

#[path = "server/startup.rs"]
mod startup;

#[path = "server/egress/upstream.rs"]
mod upstream;

/// The binary's process layer drives the server through these; re-exported
/// at the crate root so hosts import `tor_socks5_server::{run_server,
/// ServerArgs}`. SDK-11 will replace this with the real API.
#[doc(hidden)]
pub use server::{run_server, ServerArgs};
