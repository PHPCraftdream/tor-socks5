//! SOCKS5 server runtime library. The API surface covers lifecycle handles
//! and server configuration; command-line process initialization remains in
//! the binary.

#![warn(missing_docs)]

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

pub use api::{
    DnsStartupPolicy, PtBinary, Server, ServerBuilder, ServerError, ServerHandle, ServerStage,
    ServerStatus,
};
pub use config::Config;
