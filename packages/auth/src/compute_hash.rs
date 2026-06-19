//! Argon2id password hashing primitive used by the CLI when a new user
//! is added or an existing password is rotated. The result is a standard
//! PHC string and is stored verbatim on disk.

use anyhow::Result;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use crate::params::argon2_instance;

/// Hash a password with a fresh 16-byte random salt and return the PHC
/// string (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`).
///
/// # Examples
///
/// ```text
/// let hash = auth::compute_hash("hunter2").unwrap();
/// assert!(hash.starts_with("$argon2id$"));
/// assert!(auth::verify_hash(&hash, "hunter2").unwrap());
/// assert!(!auth::verify_hash(&hash, "wrong").unwrap());
/// ```
pub fn compute_hash(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes)
        .map_err(|e| anyhow::anyhow!("draw salt from OS RNG: {e}"))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("encode salt as PHC base64: {e}"))?;
    let argon = argon2_instance();
    let hash = argon
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2id hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a previously stored PHC hash.
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, `Err` only when
/// the stored hash itself is malformed.
///
/// # Examples
///
/// ```text
/// let hash = auth::compute_hash("secret").unwrap();
/// assert!(auth::verify_hash(&hash, "secret").unwrap());
/// assert!(!auth::verify_hash(&hash, "other").unwrap());
/// ```
pub fn verify_hash(stored_phc: &str, password: &str) -> Result<bool> {
    let parsed =
        PasswordHash::new(stored_phc).map_err(|e| anyhow::anyhow!("invalid stored hash: {e}"))?;
    match argon2_instance().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("argon2id verify failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_accepts_correct_password() {
        let h = compute_hash("hunter2").unwrap();
        assert!(verify_hash(&h, "hunter2").unwrap());
    }

    #[test]
    fn roundtrip_rejects_wrong_password() {
        let h = compute_hash("hunter2").unwrap();
        assert!(!verify_hash(&h, "wrong").unwrap());
    }

    #[test]
    fn each_call_uses_a_different_salt() {
        let a = compute_hash("same").unwrap();
        let b = compute_hash("same").unwrap();
        assert_ne!(a, b, "same plaintext must produce different PHC strings");
        assert!(verify_hash(&a, "same").unwrap());
        assert!(verify_hash(&b, "same").unwrap());
    }

    #[test]
    fn rejects_malformed_phc() {
        let err = verify_hash("not a phc string", "x").unwrap_err();
        assert!(format!("{err}").contains("invalid stored hash"));
    }
}
