//! Proxy pool routing for the pre and post hops.
//!
//! The crate decides which pool member to try for a target site and records
//! the outcome. It never dials: the caller supplies the connect closure, so
//! deadlines, cancellation and the transport stay with the caller.
//!
//! The pool is closed: attempts only ever visit configured members, and an
//! exhausted pool is an error, never a reason to go direct.
#![warn(missing_docs)]

mod attempt;
mod probe;
mod scope;
mod site;

pub use attempt::{run_attempts, run_attempts_with_budget, PoolError, Verdict};
pub use probe::{drive_probes, probe_round, ProbeOutcome};
pub use scope::{find_member, proxy_config, PoolScope, ScopeError, ScopeMap};
pub use site::site_key;
