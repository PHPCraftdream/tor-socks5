//! High-iteration property test for HTTP response parser — lightweight fuzz.
//! Run with `cargo test -p ptrs-gesher-webtunnel --test fuzz_response --release`.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    #[test]
    fn response_parse_10k(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = webtunnel::handshake::parse_response(&bytes);
    }
}
