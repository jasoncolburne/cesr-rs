//! Minimal CESR 2.0 Implementation
//!
//! Composable Event Streaming Representation (CESR) provides self-describing
//! cryptographic primitives with both text (Base64url) and binary representations.
//!
//! This implementation supports the subset needed for KELS:
//! - Blake3-256 digests
//! - secp256r1 (P-256) ECDSA keys and signatures
//! - ML-DSA-65/87 (FIPS 204) post-quantum keys and signatures
//! - ML-KEM-768/1024 (FIPS 203) KEM encapsulation keys and ciphertexts

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

mod base64;
mod codes;
mod digest;
mod error;
mod kem;
mod keys;
mod matter;
mod nonce;
mod signature;

pub use base64::{b64_decode, b64_encode};
pub use codes::{
    DigestCode, EncapsulationKeyCode, KemCiphertextCode, KemSeedCode, NonceCode, SignatureCode,
    SigningKeySeedCode, VerificationKeyCode,
};
pub use digest::Digest;
pub use error::CesrError;
pub use kem::{
    DecapsulationKey, EncapsulationKey, KemCiphertext, generate_ml_kem_768, generate_ml_kem_1024,
};
pub use keys::{
    SigningKey, VerificationKey, generate_ml_dsa_65, generate_ml_dsa_87, generate_secp256r1,
};
pub use matter::Matter;
pub use nonce::Nonce;
pub use signature::Signature;

/// CESR protocol version
pub const VERSION: &str = "CESR2.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_digest() {
        let data = b"test data for hashing";
        let digest = Digest::blake3_256(data);

        // Should start with 'E' code
        let qb64 = digest.qb64();
        assert!(qb64.starts_with('K'));
        assert_eq!(qb64.len(), 44); // 1 code + 43 base64

        // Verify roundtrip
        let parsed = Digest::from_qb64(&qb64).unwrap();
        assert_eq!(digest.raw(), parsed.raw());
    }

    #[test]
    fn test_secp256r1_keypair() {
        let (public, private) = keys::generate_secp256r1().unwrap();

        // Public key should start with '1AAB' (compressed) or similar
        let pub_qb64 = public.qb64();
        assert!(!pub_qb64.is_empty());

        // Sign and verify
        let message = b"test message";
        let sig = private.sign(message).unwrap();

        assert!(public.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_secp256r1_private_key_qb64() {
        let (_, private) = keys::generate_secp256r1().unwrap();

        // Private key seed should start with 'c'
        let qb64 = private.qb64();
        assert!(qb64.starts_with('c'));
        assert_eq!(qb64.len(), 44);

        // Roundtrip
        let parsed = SigningKey::from_qb64(&qb64).unwrap();
        assert_eq!(private.to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn test_ml_dsa_65_keypair() {
        let (public, private) = keys::generate_ml_dsa_65().unwrap();

        // Public key should start with 'Q'
        let pub_qb64 = public.qb64();
        assert!(pub_qb64.starts_with('Q'));
        assert_eq!(pub_qb64.len(), 2604);

        // Sign and verify
        let message = b"test message";
        let sig = private.sign(message).unwrap();

        assert!(public.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_private_key_qb64() {
        let (_, private) = keys::generate_ml_dsa_65().unwrap();

        // Private key seed should start with 'q'
        let qb64 = private.qb64();
        assert!(qb64.starts_with('q'));
        assert_eq!(qb64.len(), 44);

        // Roundtrip
        let parsed = SigningKey::from_qb64(&qb64).unwrap();
        assert_eq!(private.to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn test_ml_dsa_87_keypair() {
        let (public, private) = keys::generate_ml_dsa_87().unwrap();

        // Public key should start with '1AAU'
        let pub_qb64 = public.qb64();
        assert!(pub_qb64.starts_with("1AAU"));
        assert_eq!(pub_qb64.len(), 3460);

        // Sign and verify
        let message = b"test message";
        let sig = private.sign(message).unwrap();

        assert!(public.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_ml_dsa_87_private_key_qb64() {
        let (_, private) = keys::generate_ml_dsa_87().unwrap();

        // Private key seed should start with 'u'
        let qb64 = private.qb64();
        assert!(qb64.starts_with('u'));
        assert_eq!(qb64.len(), 44);

        // Roundtrip
        let parsed = SigningKey::from_qb64(&qb64).unwrap();
        assert_eq!(private.to_bytes(), parsed.to_bytes());
    }
}
