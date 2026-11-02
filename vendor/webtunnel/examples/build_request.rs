//! Build a WebTunnel upgrade request and parse mock responses.

use ptrs::args::Args;
use webtunnel::handshake::{build_upgrade_request, parse_response};
use webtunnel::WebTunnelConfig;

fn main() {
    // Construct a config from args.
    let mut args = Args::new();
    args.add("url", "https://example.com/secret");
    let config = WebTunnelConfig::from_args(&args).expect("config from args");

    // Build the HTTP Upgrade request.
    let request = build_upgrade_request(&config);
    print!("Upgrade request:\n{request}");

    // Parse a successful 101 response.
    let response_101 = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
    let (code, leftover) = parse_response(response_101).expect("101 should parse");
    assert_eq!(code, 101);
    assert!(leftover.is_empty());
    println!("101 response parsed OK, code={code}");

    // Parse a 404 response (should fail).
    let response_404 = b"HTTP/1.1 404 Not Found\r\n\r\n";
    let err = parse_response(response_404);
    assert!(err.is_err(), "404 should be an error");
    println!("404 correctly rejected: {err:?}");
}
