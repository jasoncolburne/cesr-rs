//! Cryptographic Keys
//!
//! CESR key primitives with support for:
//! - Ed25519: 32-byte keys, 1-char code 'D' (32 % 3 == 2)
//! - secp256r1: 33-byte compressed keys, 4-char code '1AAB' (33 % 3 == 0)

use crate::base64::{b64_decode, b64_encode};
use crate::codes::{KeyCode, SignatureCode};
use crate::error::CesrError;
use crate::matter::Matter;
use crate::signature::Signature;

use p256::ecdsa::{
    Signature as P256Sig, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::rngs::OsRng;

/// A public key with CESR encoding
#[derive(Debug, Clone)]
pub struct PublicKey {
    code: KeyCode,
    raw: Vec<u8>,
}

impl PublicKey {
    /// Create from raw bytes with specified algorithm
    pub fn from_raw(code: KeyCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        // Validate the key can be parsed
        match code {
            KeyCode::Secp256r1 => {
                if raw.len() != 33 {
                    return Err(CesrError::InvalidLength {
                        expected: 33,
                        actual: raw.len(),
                    });
                }
                P256VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
            }
        }
        Ok(PublicKey { code, raw })
    }

    /// Get the key algorithm
    pub fn algorithm(&self) -> KeyCode {
        self.code
    }

    /// Verify a signature over a message
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CesrError> {
        match self.code {
            KeyCode::Secp256r1 => {
                let verifying_key = P256VerifyingKey::from_sec1_bytes(&self.raw)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let sig = P256Sig::from_slice(signature.raw())
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| CesrError::VerificationFailed)
            }
        }
    }
}

impl Matter for PublicKey {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        match self.code {
            KeyCode::Secp256r1 => {
                // 33 bytes, 4-char code '1AAB'
                // 33 bytes = 44 base64 chars, 4 + 44 = 48
                // Prepend 3 zero bytes, encode, replace first 4 chars
                let mut padded = vec![0u8; 3];
                padded.extend_from_slice(&self.raw);
                let encoded = b64_encode(&padded);
                format!("1AAJ{}", &encoded[4..])
            }
        }
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = KeyCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let raw = match code {
            KeyCode::Secp256r1 => {
                // Replace '1AAB' with 'AAAA', decode, skip first 3 bytes
                let to_decode = format!("AAAA{}", &qb64[4..]);
                let decoded = b64_decode(&to_decode)?;
                decoded[3..].to_vec()
            }
        };

        PublicKey::from_raw(code, raw)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.raw == other.raw
    }
}

impl Eq for PublicKey {}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PublicKey::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

/// A private key for signing (not CESR-encoded for security)
#[derive(Clone)]
pub enum PrivateKey {
    Secp256r1(P256SigningKey),
}

impl PrivateKey {
    /// Get the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Secp256r1(sk) => {
                let vk = sk.verifying_key();
                // Compressed SEC1 encoding
                let raw = vk.to_encoded_point(true).as_bytes().to_vec();
                PublicKey {
                    code: KeyCode::Secp256r1,
                    raw,
                }
            }
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Signature, CesrError> {
        match self {
            PrivateKey::Secp256r1(sk) => {
                let sig: P256Sig = sk.sign(message);
                Signature::from_raw(SignatureCode::Secp256r1, sig.to_bytes().to_vec())
            }
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> KeyCode {
        match self {
            PrivateKey::Secp256r1(_) => KeyCode::Secp256r1,
        }
    }

    /// Export raw private key bytes (use with caution)
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Secp256r1(sk) => sk.to_bytes().to_vec(),
        }
    }

    /// Import from raw bytes
    pub fn from_bytes(code: KeyCode, bytes: &[u8]) -> Result<Self, CesrError> {
        match code {
            KeyCode::Secp256r1 => {
                let sk = P256SigningKey::from_slice(bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Ok(PrivateKey::Secp256r1(sk))
            }
        }
    }

    /// Encode as qualified Base64 (qb64)
    pub fn qb64(&self) -> String {
        let raw = self.to_bytes();
        // Both Ed25519 and Secp256r1 seeds are 32 bytes with 1-char codes
        // Prepend zero byte for alignment, encode, replace first char with code
        let mut padded = vec![0u8];
        padded.extend_from_slice(&raw);
        let encoded = b64_encode(&padded);
        let code = match self {
            PrivateKey::Secp256r1(_) => "Q",
        };
        format!("{}{}", code, &encoded[1..])
    }

    /// Decode from qualified Base64 (qb64)
    pub fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        use crate::codes::SeedCode;

        let code = SeedCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        // Replace code char with 'A', decode, skip first byte
        let to_decode = format!("A{}", &qb64[1..]);
        let decoded = b64_decode(&to_decode)?;
        let raw = decoded[1..].to_vec();

        match code {
            SeedCode::Secp256r1 => PrivateKey::from_bytes(KeyCode::Secp256r1, &raw),
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKey::Secp256r1(_) => write!(f, "PrivateKey::Secp256r1([REDACTED])"),
        }
    }
}

/// Generate a new secp256r1 (P-256) key pair
pub fn generate_secp256r1() -> Result<(PublicKey, PrivateKey), CesrError> {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let private = PrivateKey::Secp256r1(signing_key);
    let public = private.public_key();
    Ok((public, private))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256r1_generate() {
        let (public, private) = generate_secp256r1().unwrap();
        assert_eq!(public.algorithm(), KeyCode::Secp256r1);
        assert_eq!(public.raw().len(), 33); // Compressed
        assert_eq!(private.algorithm(), KeyCode::Secp256r1);
    }

    #[test]
    fn test_secp256r1_qb64() {
        let (public, _) = generate_secp256r1().unwrap();
        let qb64 = public.qb64();
        assert!(qb64.starts_with("1AAJ"));
        assert_eq!(qb64.len(), 48);

        let parsed = PublicKey::from_qb64(&qb64).unwrap();
        assert_eq!(public, parsed);
    }

    #[test]
    fn test_secp256r1_sign_verify() {
        let (public, private) = generate_secp256r1().unwrap();
        let message = b"Test message for ECDSA signing";

        let signature = private.sign(message).unwrap();
        assert!(public.verify(message, &signature).is_ok());
        assert!(public.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_private_key_export_import() {
        let (original_public, original_private) = generate_secp256r1().unwrap();
        let bytes = original_private.to_bytes();

        let imported_private = PrivateKey::from_bytes(KeyCode::Secp256r1, &bytes).unwrap();
        let imported_public = imported_private.public_key();

        assert_eq!(original_public, imported_public);
    }
}
