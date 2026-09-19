//! The local UDP/TCP DNS listener speaking the plain DNS wire format.
//!
//! Implementation lands in a follow-up task: accept client queries, resolve
//! them through the DoH client (cache first), and answer on the wire.
