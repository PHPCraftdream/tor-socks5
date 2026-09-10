mod dns_cache_tests;
mod dns_save_tests;
mod dns_timestamp_tests;
mod probe_coalesce_tests;
mod probe_identity_tests;
mod probe_ordering_tests;
mod probe_race_tests;
mod transport_tests;

use bridge_line::BridgeLine;
use std::str::FromStr;

fn bridge_for(addr: std::net::SocketAddr) -> BridgeLine {
    BridgeLine::from_str(&format!(
        "obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    ))
    .expect("synthetic bridge line parses")
}
