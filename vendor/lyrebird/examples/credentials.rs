//! Demonstrate lyrebird helper functions without a tor daemon.

use fast_socks5::util::target_addr::TargetAddr;
use lyrebird::{arg_string_from_creds, resolve_target_addr};
use std::net::SocketAddr;

fn main() {
    // arg_string_from_creds: join username + password into the PT arg string.
    let creds = Some(("cert=AAA".to_string(), ";iat-mode=0".to_string()));
    let joined = arg_string_from_creds(creds);
    assert_eq!(joined, "cert=AAA;iat-mode=0");
    println!("arg_string_from_creds: {joined}");

    // Empty creds → empty string.
    let empty = arg_string_from_creds(None);
    assert!(empty.is_empty());
    println!("empty creds: \"{empty}\"");

    // resolve_target_addr: IP address passes through.
    let addr = TargetAddr::Ip("127.0.0.1:9000".parse::<SocketAddr>().unwrap());
    let resolved = resolve_target_addr(&addr).expect("IP should resolve");
    assert_eq!(resolved.to_string(), "127.0.0.1:9000");
    println!("resolved: {resolved}");

    // Domain address fails (PT does not do DNS).
    let domain = TargetAddr::Domain("example.com".into(), 443);
    let err = resolve_target_addr(&domain);
    assert!(err.is_err(), "domain should fail");
    println!("domain correctly rejected: {err:?}");
}
