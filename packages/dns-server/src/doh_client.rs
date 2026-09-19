//! DNS-over-HTTPS client whose every exchange runs through the live Tor
//! tunnel ([`arti_wrapper::TorTunnel::connect`]) instead of the direct
//! network.
//!
//! Implementation lands in a follow-up task: encode the query with
//! `hickory-proto`, POST it to a [`crate::DohProvider`] over rustls, decode
//! the wire-format reply into a [`crate::ResolvedAnswer`].
