//! SOCKS5 server runtime library. The API surface covers lifecycle handles
//! and server configuration; command-line process initialization remains in
//! the binary.

mod api;
mod config;

#[path = "server/dns_wiring.rs"]
mod dns_wiring;

/// Onion-service hosting shell (`spawn_services`), behind `onion-service`.
mod onion;

#[path = "server/egress/route.rs"]
mod route;

// This is an internal implementation module, not part of the SDK surface.
#[path = "server/server.rs"]
mod server;

#[path = "server/startup.rs"]
mod startup;

#[path = "server/egress/upstream.rs"]
mod upstream;

// The bridges CLI needs this one validation helper; keep the route
// implementation private rather than exposing the server's internal modules.
#[doc(hidden)]
pub use route::reject_unsupported_pool;

pub use api::{
    DnsStartupPolicy, Server, ServerBuilder, ServerError, ServerHandle, ServerStage, ServerStatus,
};
pub use config::Config;
