mod dns_tests;
mod probe_tests;
mod transport_tests;

use bridge_line::BridgeLine;
use std::str::FromStr;

fn bridge_for(addr: std::net::SocketAddr) -> BridgeLine {
    BridgeLine::from_str(&format!(
        "obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    ))
    .expect("synthetic bridge line parses")
}
