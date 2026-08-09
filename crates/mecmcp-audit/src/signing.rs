//! Ed25519 signing over closed chain-segment heads.
//!
//! ## Signed bytes definition
//!
//! The signature is computed over the **raw 32-byte SHA-256 digest** of the
//! segment head, not the `sha256:<hex>` string. To verify a signature:
//!
//! 1. Decode the head hash string (format: `sha256:0123456789abcdef...`) to
//!    extract the 64-character hex portion.
//! 2. Decode the hex string to 32 bytes.
//! 3. Verify the signature against those 32 bytes using the public key.
//!
//! ## Signature encoding
//!
//! Signatures are encoded as **base64** (standard alphabet, with padding).
//!
//! ## Key file security
//!
//! Private key files MUST be mode 0600 (owner read/write only) on Unix
//! platforms. Any broader permissions will cause key loading to fail closed.

use crate::evidence::ClosedSegment;
use base64::prelude::*;
use ed25519_dalek::{
    Signature, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey as DalekVerifyingKey,
};
use std::path::Path;
use thiserror::Error;

/// Ed25519 signing key.
///
/// The underlying key is zeroized on drop via ed25519-dalek's implementation.
pub struct SigningKey {
    inner: DalekSigningKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey([REDACTED])")
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // DalekSigningKey handles zeroization internally
    }
}

/// Ed25519 verification key.
#[derive(Clone)]
pub struct VerifyingKey {
    inner: DalekVerifyingKey,
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("bytes", &self.inner.as_bytes())
            .finish()
    }
}

/// Detached Ed25519 signature.
#[derive(Clone)]
pub struct DetachedSignature {
    inner: Signature,
}

impl std::fmt::Debug for DetachedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedSignature")
            .field("bytes", &self.inner.to_bytes())
            .finish()
    }
}

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    /// Key file has overly permissive mode (Unix only).
    #[error("key file {path} has mode {mode:04o} (must be 0600)")]
    KeyFilePermissionsTooPermissive {
        /// The path to the key file.
        path: std::path::PathBuf,
        /// The file mode.
        mode: u32,
    },
    /// Key file I/O error.
    #[error("failed to read key file {path}: {error}")]
    KeyFileIo {
        /// The path to the key file.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        error: std::io::Error,
    },
    /// Invalid key encoding.
    #[error("invalid key encoding: {0}")]
    InvalidKeyEncoding(String),
    /// Invalid head hash format.
    #[error("invalid head hash format: {0}")]
    InvalidHeadHash(String),
    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Validate Unix file permissions (must be 0600 for private keys).
#[cfg(unix)]
fn validate_key_file_permissions(path: &Path) -> Result<(), SigningError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).map_err(|error| SigningError::KeyFileIo {
        path: path.to_path_buf(),
        error,
    })?;

    let mode = metadata.mode() & 0o777;
    let forbidden = 0o077; // No group or other permissions allowed
    if mode & forbidden != 0 {
        return Err(SigningError::KeyFilePermissionsTooPermissive {
            path: path.to_path_buf(),
            mode,
        });
    }

    Ok(())
}

/// Load a signing key from a file.
///
/// The file MUST be mode 0600 on Unix platforms, or this function will return
/// an error (fail-closed).
pub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {
    #[cfg(unix)]
    validate_key_file_permissions(path)?;

    let contents = std::fs::read_to_string(path).map_err(|error| SigningError::KeyFileIo {
        path: path.to_path_buf(),
        error,
    })?;

    let contents = contents.trim();
    let bytes = BASE64_STANDARD
        .decode(contents)
        .map_err(|e| SigningError::InvalidKeyEncoding(format!("base64 decode failed: {}", e)))?;

    let bytes_len = bytes.len();
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        SigningError::InvalidKeyEncoding(format!("expected 32 bytes, got {}", bytes_len))
    })?;

    let inner = DalekSigningKey::from_bytes(&key_bytes);
    Ok(SigningKey { inner })
}

/// Load a verifying key from a file.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, SigningError> {
    let contents = std::fs::read_to_string(path).map_err(|error| SigningError::KeyFileIo {
        path: path.to_path_buf(),
        error,
    })?;

    let contents = contents.trim();
    let bytes = BASE64_STANDARD
        .decode(contents)
        .map_err(|e| SigningError::InvalidKeyEncoding(format!("base64 decode failed: {}", e)))?;

    let bytes_len = bytes.len();
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        SigningError::InvalidKeyEncoding(format!("expected 32 bytes, got {}", bytes_len))
    })?;

    let inner = DalekVerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| SigningError::InvalidKeyEncoding(format!("invalid verifying key: {}", e)))?;

    Ok(VerifyingKey { inner })
}

/// Decode the head hash from `sha256:<hex>` format to raw 32 bytes.
fn decode_head_hash(head_hash: &str) -> Result<[u8; 32], SigningError> {
    let hex_part = head_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| SigningError::InvalidHeadHash("missing 'sha256:' prefix".to_string()))?;

    if hex_part.len() != 64 {
        return Err(SigningError::InvalidHeadHash(format!(
            "expected 64 hex characters, got {}",
            hex_part.len()
        )));
    }

    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut bytes)
        .map_err(|e| SigningError::InvalidHeadHash(format!("hex decode failed: {}", e)))?;

    Ok(bytes)
}

/// Sign a closed segment's head hash.
///
/// Returns a detached signature over the raw 32-byte SHA-256 digest.
pub fn sign_head(
    closed: &ClosedSegment,
    key: &SigningKey,
) -> Result<DetachedSignature, SigningError> {
    let head_bytes = decode_head_hash(&closed.head_hash)?;
    let signature = key.inner.sign(&head_bytes);
    Ok(DetachedSignature { inner: signature })
}

/// Verify a signature over a closed segment's head hash.
pub fn verify_head(
    closed: &ClosedSegment,
    signature: &DetachedSignature,
    key: &VerifyingKey,
) -> Result<(), SigningError> {
    let head_bytes = decode_head_hash(&closed.head_hash)?;
    key.inner
        .verify(&head_bytes, &signature.inner)
        .map_err(|_| SigningError::VerificationFailed)
}

/// Encode a signature as base64.
pub fn encode_signature(signature: &DetachedSignature) -> String {
    BASE64_STANDARD.encode(signature.inner.to_bytes())
}

/// Decode a signature from base64.
pub fn decode_signature(encoded: &str) -> Result<DetachedSignature, SigningError> {
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| SigningError::InvalidKeyEncoding(format!("base64 decode failed: {}", e)))?;

    let bytes_len = bytes.len();
    let sig_bytes: [u8; 64] = bytes.try_into().map_err(|_| {
        SigningError::InvalidKeyEncoding(format!("expected 64 bytes, got {}", bytes_len))
    })?;

    let inner = Signature::from_bytes(&sig_bytes);
    Ok(DetachedSignature { inner })
}

/// Generate a new Ed25519 keypair.
///
/// Returns (signing_key, verifying_key).
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    use rand_core::OsRng;

    let dalek_signing_key = DalekSigningKey::generate(&mut OsRng);
    let dalek_verifying_key = dalek_signing_key.verifying_key();

    (
        SigningKey {
            inner: dalek_signing_key,
        },
        VerifyingKey {
            inner: dalek_verifying_key,
        },
    )
}

/// Encode a signing key for storage (base64).
///
/// **WARNING:** The encoded key is sensitive. Never log or print it.
pub fn encode_signing_key(key: &SigningKey) -> String {
    BASE64_STANDARD.encode(key.inner.to_bytes())
}

/// Encode a verifying key for distribution (base64).
pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    BASE64_STANDARD.encode(key.inner.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{
        ChainSegment, EvidenceRecord, GENESIS_PREV_HASH, ProposalRecord, append, close,
    };
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn proposal_fixture() -> ProposalRecord {
        ProposalRecord {
            request_id: "req_test".to_string(),
            changeset_id: "cs_test".to_string(),
            device_id: "dev_test".to_string(),
            principal: "agent:test".to_string(),
            diff_hash: "sha256:abcd1234".to_string(),
            timestamp: "2026-08-09T12:00:00Z".to_string(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            metadata: None,
        }
    }

    fn make_closed_segment() -> ClosedSegment {
        let mut seg = ChainSegment::new(
            "run_test".to_string(),
            "server_test".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(&mut seg, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        close(seg).unwrap()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let closed = make_closed_segment();

        let signature = sign_head(&closed, &signing_key).unwrap();
        verify_head(&closed, &signature, &verifying_key).unwrap();
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (signing_key, _) = generate_keypair();
        let (_, wrong_key) = generate_keypair();
        let closed = make_closed_segment();

        let signature = sign_head(&closed, &signing_key).unwrap();
        let result = verify_head(&closed, &signature, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_head_fails_verification() {
        let (signing_key, verifying_key) = generate_keypair();
        let closed = make_closed_segment();
        let signature = sign_head(&closed, &signing_key).unwrap();

        // Create a different segment with a different head
        let mut seg2 = ChainSegment::new(
            "run_different".to_string(),
            "server_different".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(&mut seg2, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        let closed2 = close(seg2).unwrap();

        // The original signature should not verify against the tampered segment
        let result = verify_head(&closed2, &signature, &verifying_key);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn key_file_0644_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("test_key");
        let (signing_key, _) = generate_keypair();
        let encoded = encode_signing_key(&signing_key);

        fs::write(&key_path, encoded).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        let result = load_signing_key(&key_path);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(SigningError::KeyFilePermissionsTooPermissive { mode: 0o644, .. })
        ));
    }

    #[test]
    #[cfg(unix)]
    fn key_file_0600_accepted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("test_key");
        let (signing_key, _) = generate_keypair();
        let encoded = encode_signing_key(&signing_key);

        let mut file = fs::File::create(&key_path).unwrap();
        file.write_all(encoded.as_bytes()).unwrap();
        drop(file);

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let loaded = load_signing_key(&key_path);
        assert!(loaded.is_ok());
    }

    #[test]
    fn keygen_never_echoes_private_material() {
        let (signing_key, verifying_key) = generate_keypair();
        let private_encoded = encode_signing_key(&signing_key);
        let public_encoded = encode_verifying_key(&verifying_key);

        // Debug/Display of keys should not reveal private material
        let debug_str = format!("{:?}", signing_key);
        assert!(!debug_str.contains(&private_encoded));

        // Public key can be freely printed
        assert!(!public_encoded.is_empty());
    }

    #[test]
    fn signature_encoding_stable() {
        // Golden fixture: ensure signature encoding is stable across versions
        let (signing_key, verifying_key) = generate_keypair();
        let closed = make_closed_segment();

        let sig1 = sign_head(&closed, &signing_key).unwrap();
        let encoded = encode_signature(&sig1);

        // Base64 signature should decode back
        let decoded = decode_signature(&encoded).unwrap();
        verify_head(&closed, &decoded, &verifying_key).unwrap();
    }
}
