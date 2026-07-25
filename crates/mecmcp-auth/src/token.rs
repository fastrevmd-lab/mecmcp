//! Token minting, versioned digests, and constant-time verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Raw random bytes behind one token secret.
const SECRET_BYTES: usize = 32;
/// Length of 32 random bytes encoded as unpadded base64url.
const ENCODED_SECRET_BYTES: usize = 43;
/// Prefix identifying the digest algorithm on disk.
const DIGEST_PREFIX: &str = "sha256:";

/// Error while minting or decoding token material.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The operating-system CSPRNG failed.
    #[error("operating-system random source failed")]
    Random,
    /// A stored token digest is malformed.
    #[error("invalid token digest: {0}")]
    InvalidDigest(String),
}

/// A freshly minted bearer secret.
///
/// Implements neither `Clone`, `Debug`, `Display`, nor `Serialize`, so it
/// cannot be logged or persisted by accident. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TokenSecret(String);

impl TokenSecret {
    /// Mint 256 random bits and return the plaintext with its stored digest.
    ///
    /// The plaintext is expected to leave the process exactly once, printed by
    /// a `token add` or `token rotate` command.
    pub fn mint() -> Result<(Self, TokenDigest), TokenError> {
        let mut random = [0_u8; SECRET_BYTES];
        getrandom::fill(&mut random).map_err(|_| TokenError::Random)?;
        let encoded = base64url_no_pad(&random);
        debug_assert_eq!(
            encoded.len(),
            ENCODED_SECRET_BYTES,
            "base64url encoding of {SECRET_BYTES} bytes must yield {ENCODED_SECRET_BYTES} chars"
        );
        random.zeroize();
        let digest = TokenDigest::from_secret(&encoded);
        Ok((Self(encoded), digest))
    }

    /// Expose the plaintext for the single write that prints it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

/// Versioned SHA-256 digest of a token secret, as stored in `tokens.json`.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenDigest(String);

impl TokenDigest {
    /// Compute the stored digest for a secret.
    #[must_use]
    pub fn from_secret(secret: &str) -> Self {
        let hashed = Sha256::digest(secret.as_bytes());
        Self(format!("{DIGEST_PREFIX}{}", base64url_no_pad(&hashed)))
    }

    /// Constant-time comparison of a candidate secret against this digest.
    #[must_use]
    pub fn verify(&self, candidate: &str) -> bool {
        let computed = Self::from_secret(candidate);
        computed.0.as_bytes().ct_eq(self.0.as_bytes()).into()
    }

    /// The `sha256:`-prefixed digest string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Digests are not secrets, but they are not useful in logs either.
        f.write_str("TokenDigest(sha256:…)")
    }
}

impl Serialize for TokenDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TokenDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if !raw.starts_with(DIGEST_PREFIX) {
            return Err(serde::de::Error::custom(format!(
                "token digest must start with '{DIGEST_PREFIX}'"
            )));
        }
        Ok(Self(raw))
    }
}

/// Encode bytes as unpadded base64url without pulling in a base64 crate.
fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let indices = [
            (triple >> 18) & 0x3F,
            (triple >> 12) & 0x3F,
            (triple >> 6) & 0x3F,
            triple & 0x3F,
        ];
        let emit = chunk.len() + 1;
        for index in indices.iter().take(emit) {
            out.push(ALPHABET[*index as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_secret_verifies_against_its_own_digest() {
        let (secret, digest) = TokenSecret::mint().expect("mint");
        assert!(digest.verify(secret.expose_secret()));
    }

    #[test]
    fn digest_rejects_a_different_secret() {
        let (_secret, digest) = TokenSecret::mint().expect("mint");
        let (other, _) = TokenSecret::mint().expect("mint");
        assert!(!digest.verify(other.expose_secret()));
    }

    #[test]
    fn minted_secret_is_43_chars_of_base64url_no_pad() {
        let (secret, _) = TokenSecret::mint().expect("mint");
        assert_eq!(secret.expose_secret().len(), ENCODED_SECRET_BYTES);
        assert!(!secret.expose_secret().contains('='));
    }

    #[test]
    fn digest_is_prefixed_and_round_trips_through_serde() {
        let (_secret, digest) = TokenSecret::mint().expect("mint");
        assert!(digest.as_str().starts_with(DIGEST_PREFIX));
        let json = serde_json::to_string(&digest).expect("serialize");
        let back: TokenDigest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(digest, back);
    }

    #[test]
    fn digest_without_prefix_is_rejected() {
        let err = serde_json::from_str::<TokenDigest>("\"deadbeef\"");
        assert!(err.is_err());
    }

    #[test]
    fn two_mints_differ() {
        let (a, _) = TokenSecret::mint().expect("mint");
        let (b, _) = TokenSecret::mint().expect("mint");
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn digest_matches_the_format_both_existing_servers_write() {
        // Known-answer: SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015
        //                                a3bf4f1b2b0b822cd15d6c15b0f00a08
        // base64url-unpadded of those 32 bytes:
        let digest = TokenDigest::from_secret("test");
        assert_eq!(
            digest.as_str(),
            "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
        );
    }
}
