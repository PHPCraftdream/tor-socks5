use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_response_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = webtunnel::handshake::parse_response(&bytes);
    }

    #[test]
    fn parse_response_truncated_valid(offset in 0usize..150) {
        let full = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\nDATA";
        if offset < full.len() {
            let _ = webtunnel::handshake::parse_response(&full[..offset]);
        }
    }
}
