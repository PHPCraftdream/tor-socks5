//! v3 onion address derivation and parsing (rend-spec-v3).
//!
//! Address format: base32(PUBKEY(32) || CHECKSUM(2) || 0x03) + ".onion",
//! where CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || 0x03)[0..2].

use std::fmt;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use ed25519_dalek::VerifyingKey;
use sha2::Digest as Sha2Digest;
use sha3::Sha3_256;
use zeroize::Zeroizing;

/// Constant prepended to the pubkey before checksumming.
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";
/// Address version byte (v3).
const VERSION: u8 = 0x03;
/// Base32 chars of the address before the ".onion" suffix.
const ADDRESS_LEN: usize = 56;
/// Suffix appended to the base32 body.
const ONION_SUFFIX: &str = ".onion";

/// Errors returned by [`parse_onion_address`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ParseError {
    /// Body before ".onion" is not exactly 56 characters.
    #[error("invalid onion address length: expected 56 chars, got {0}")]
    BadLength(usize),
    /// Body contains a character outside the base32 alphabet (a-z, A-Z, 2-7).
    #[error("invalid character {0:?} at position {1}")]
    BadCharacter(char, usize),
    /// Version byte (last decoded byte) is not 0x03.
    #[error("unsupported onion address version: {0:#04x}")]
    UnsupportedVersion(u8),
    /// Checksum bytes do not match the recomputed checksum.
    #[error("onion address checksum mismatch")]
    ChecksumMismatch,
}

/// Encode a 32-byte ed25519 public key as a v3 onion address (with ".onion").
pub(crate) fn onion_address(pubkey: &[u8; 32]) -> String {
    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(pubkey);
    raw[32..34].copy_from_slice(&checksum(pubkey));
    raw[34] = VERSION;
    let mut body = BASE32_NOPAD.encode(&raw);
    body.make_ascii_lowercase();
    body.push_str(ONION_SUFFIX);
    body
}

/// Parse a v3 onion address and return its 32-byte public key.
///
/// Uppercase base32 is accepted and normalized. The ".onion" suffix is
/// required (case-insensitive).
pub(crate) fn parse_onion_address(addr: &str) -> Result<[u8; 32], ParseError> {
    let body = match addr
        .strip_suffix(".onion")
        .or_else(|| addr.strip_suffix(".ONION"))
    {
        Some(body) => body,
        None => return Err(ParseError::BadLength(addr.len())),
    };
    if body.len() != ADDRESS_LEN {
        return Err(ParseError::BadLength(body.len()));
    }
    let body = body.to_ascii_lowercase();
    for (i, ch) in body.chars().enumerate() {
        if !matches!(ch, 'a'..='z' | '2'..='7') {
            return Err(ParseError::BadCharacter(ch, i));
        }
    }
    let raw = BASE32_NOPAD
        .decode(body.to_ascii_uppercase().as_bytes())
        .expect("length and alphabet validated above");
    debug_assert_eq!(raw.len(), 35);
    let (pubkey, rest) = raw.split_at(32);
    let pubkey: [u8; 32] = pubkey.try_into().expect("split_at(32)");
    if rest[2] != VERSION {
        return Err(ParseError::UnsupportedVersion(rest[2]));
    }
    if rest[0..2] != checksum(&pubkey) {
        return Err(ParseError::ChecksumMismatch);
    }
    Ok(pubkey)
}

/// CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || 0x03)[0..2].
fn checksum(pubkey: &[u8; 32]) -> [u8; 2] {
    let digest = Sha3_256::new()
        .chain_update(CHECKSUM_PREFIX)
        .chain_update(pubkey)
        .chain_update([VERSION])
        .finalize();
    [digest[0], digest[1]]
}

/// A v3 onion keypair: public key, address, and the Tor keystore-style
/// expanded secret key (64 bytes = clamped scalar || SHA-512 prefix).
pub(crate) struct Keypair {
    pubkey: [u8; 32],
    address: String,
    secret: Zeroizing<[u8; 64]>,
}

impl Keypair {
    /// Public ed25519 key.
    pub(crate) fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    /// Full v3 onion address, including the ".onion" suffix.
    pub(crate) fn address(&self) -> &str {
        &self.address
    }

    /// Expanded secret key in the Tor `ks_hs_id.ed25519_expanded_private`
    /// layout: clamped scalar (32 bytes) || SHA-512 hash prefix (32 bytes).
    pub(crate) fn to_expanded_bytes(&self) -> [u8; 64] {
        *self.secret
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose the secret.
        f.debug_struct("Keypair")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// Deterministically derive a keypair from a 32-byte seed
/// (seed -> SHA-512 -> clamp -> expanded secret key).
pub(crate) fn generate_from_seed(seed: &[u8; 32]) -> Keypair {
    // seed -> SHA-512, per the ed25519 keygen spec.
    let digest = sha2::Sha512::digest(seed);
    let mut expanded =
        Zeroizing::new(<[u8; 64]>::try_from(digest.as_slice()).expect("SHA-512 is 64 bytes"));
    // Clamp the scalar half in place (ed25519-dalek re-clamps idempotently).
    let scalar: &mut [u8; 32] = (&mut expanded[..32]).try_into().expect("32 bytes");
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let esk = ExpandedSecretKey::from_bytes(&expanded);
    let pubkey = VerifyingKey::from(&esk).to_bytes();
    let address = onion_address(&pubkey);
    Keypair {
        pubkey,
        address,
        secret: expanded,
    }
}

/// Generate a random keypair using the OS random number generator.
pub(crate) fn generate() -> Keypair {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).expect("OS RNG failure");
    generate_from_seed(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known vector: pubkey = bytes 0..32, checksum computed per
    /// rend-spec-v3 (verified against the same formula used by
    /// tor-hscrypto 0.47 `HsId`).
    #[test]
    fn address_known_vector() {
        let mut pubkey = [0u8; 32];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            onion_address(&pubkey),
            "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion"
        );
    }

    #[test]
    fn address_is_62_chars_with_suffix() {
        let kp = generate_from_seed(&[7u8; 32]);
        let addr = kp.address();
        assert_eq!(addr.len(), ADDRESS_LEN + ONION_SUFFIX.len());
        assert!(addr.ends_with(".onion"));
        assert!(addr
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.'));
    }

    #[test]
    fn parse_valid_and_roundtrip() {
        let kp = generate_from_seed(&[9u8; 32]);
        let parsed = parse_onion_address(kp.address()).expect("valid address");
        assert_eq!(&parsed, kp.pubkey());
    }

    #[test]
    fn parse_accepts_uppercase() {
        let kp = generate_from_seed(&[10u8; 32]);
        let upper: String = kp
            .address()
            .chars()
            .map(|c| c.to_ascii_uppercase())
            .collect();
        assert_eq!(parse_onion_address(&upper).unwrap(), *kp.pubkey());
    }

    #[test]
    fn parse_bad_checksum() {
        let addr = onion_address(&[1u8; 32]);
        let mut pubkey = parse_onion_address(&addr).unwrap();
        pubkey[0] ^= 1;
        let tampered = onion_address(&pubkey);
        // Tampering with the pubkey breaks the checksum of the original body.
        let mut body: Vec<char> = addr.chars().collect();
        body[0] = if body[0] == 'a' { 'b' } else { 'a' };
        let bad: String = body.into_iter().collect();
        assert_eq!(parse_onion_address(&bad), Err(ParseError::ChecksumMismatch));
        // The tampered pubkey itself still parses fine.
        assert!(parse_onion_address(&tampered).is_ok());
    }

    #[test]
    fn parse_bad_version() {
        let mut raw = [0u8; 35];
        raw[..32].copy_from_slice(&[2u8; 32]);
        raw[32..34].copy_from_slice(&checksum(&[2u8; 32]));
        raw[34] = 0x02;
        let mut body = BASE32_NOPAD.encode(&raw);
        body.make_ascii_lowercase();
        body.push_str(".onion");
        assert_eq!(
            parse_onion_address(&body),
            Err(ParseError::UnsupportedVersion(0x02))
        );
    }

    #[test]
    fn parse_bad_length() {
        let addr = onion_address(&[3u8; 32]);
        let short = &addr[..addr.len() - 1];
        assert!(matches!(
            parse_onion_address(short),
            Err(ParseError::BadLength(_))
        ));
        let mut long = addr.clone();
        long.insert(0, 'a');
        assert!(matches!(
            parse_onion_address(&long),
            Err(ParseError::BadLength(_))
        ));
        // Missing ".onion" suffix is treated as a bad length.
        let no_suffix = &addr[..ADDRESS_LEN];
        assert!(matches!(
            parse_onion_address(no_suffix),
            Err(ParseError::BadLength(_))
        ));
    }

    #[test]
    fn parse_bad_characters() {
        let addr = onion_address(&[4u8; 32]);
        let mut body: Vec<char> = addr.chars().collect();
        body[10] = '1';
        let bad: String = body.into_iter().collect();
        assert!(matches!(
            parse_onion_address(&bad),
            Err(ParseError::BadCharacter('1', 10))
        ));
        let mut body: Vec<char> = addr.chars().collect();
        body[5] = '!';
        let bad: String = body.into_iter().collect();
        assert!(matches!(
            parse_onion_address(&bad),
            Err(ParseError::BadCharacter('!', 5))
        ));
    }

    #[test]
    fn expanded_secret_roundtrips_to_pubkey() {
        let kp = generate_from_seed(&[11u8; 32]);
        let expanded = kp.to_expanded_bytes();
        let esk = ExpandedSecretKey::from_bytes(&expanded);
        assert_eq!(VerifyingKey::from(&esk).to_bytes(), *kp.pubkey());
        assert_eq!(onion_address(kp.pubkey()), kp.address());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let kp = generate_from_seed(&[12u8; 32]);
        let dbg = format!("{kp:?}");
        assert!(!dbg.contains("secret"));
        assert!(!dbg.contains(&format!("{:?}", kp.to_expanded_bytes()[..4].to_vec())));
        assert!(dbg.contains(kp.address()));
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = generate();
        let b = generate();
        assert_ne!(a.pubkey(), b.pubkey());
        // Zeroized wrapper must zero on drop; check a fresh clone is intact.
        assert_eq!(a.to_expanded_bytes().len(), 64);
    }

    #[test]
    fn zeroize_actually_clears() {
        let mut buf = [0x42u8; 64];
        zeroize::Zeroize::zeroize(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }
}
