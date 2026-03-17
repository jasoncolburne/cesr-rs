//! Cryptographic Keys
//!
//! CESR key primitives with support for:
//! - secp256r1: 33-byte compressed keys, 4-char code '1AAJ' (33 % 3 == 0)
//! - ML-DSA-65: 1952-byte public keys, 1-char code 'b' (1952 % 3 == 2)

use p256::ecdsa::{
    Signature as P256Sig, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::RngCore;
use rand::rngs::OsRng;

use fips204::traits::{
    KeyGen as FipsKeyGen, SerDes as FipsSerDes, Signer as FipsSigner, Verifier as FipsVerifier,
};
use fips204::{ml_dsa_65, ml_dsa_87};

use crate::base64::{b64_decode, b64_encode};
use crate::codes::{SeedCode, SignatureCode, SigningKeyCode};
use crate::error::CesrError;
use crate::matter::Matter;
use crate::signature::Signature;

/// A public key with CESR encoding
#[derive(Debug, Clone)]
pub struct PublicKey {
    code: SigningKeyCode,
    raw: Vec<u8>,
}

impl PublicKey {
    /// Create from raw bytes with specified algorithm
    pub fn from_raw(code: SigningKeyCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        // Validate the key can be parsed
        match code {
            SigningKeyCode::Secp256r1 => {
                if raw.len() != 33 {
                    return Err(CesrError::InvalidLength {
                        expected: 33,
                        actual: raw.len(),
                    });
                }
                P256VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
            }
            SigningKeyCode::MlDsa65 => {
                if raw.len() != 1952 {
                    return Err(CesrError::InvalidLength {
                        expected: 1952,
                        actual: raw.len(),
                    });
                }
                let bytes: [u8; 1952] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid ML-DSA-65 key length".into()))?;
                ml_dsa_65::PublicKey::try_from_bytes(bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
            }
            SigningKeyCode::MlDsa87 => {
                if raw.len() != 2592 {
                    return Err(CesrError::InvalidLength {
                        expected: 2592,
                        actual: raw.len(),
                    });
                }
                let bytes: [u8; 2592] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid ML-DSA-87 key length".into()))?;
                ml_dsa_87::PublicKey::try_from_bytes(bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
            }
        }
        Ok(PublicKey { code, raw })
    }

    /// Get the key algorithm
    pub fn algorithm(&self) -> SigningKeyCode {
        self.code
    }

    /// Verify a signature over a message
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CesrError> {
        match self.code {
            SigningKeyCode::Secp256r1 => {
                let verifying_key = P256VerifyingKey::from_sec1_bytes(&self.raw)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let sig = P256Sig::from_slice(signature.raw())
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| CesrError::VerificationFailed)
            }
            SigningKeyCode::MlDsa65 => {
                let pk_bytes: [u8; 1952] = self
                    .raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid key length".into()))?;
                let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let sig_bytes: [u8; 3309] = signature
                    .raw()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid signature length".into()))?;
                if pk.verify(message, &sig_bytes, &[]) {
                    Ok(())
                } else {
                    Err(CesrError::VerificationFailed)
                }
            }
            SigningKeyCode::MlDsa87 => {
                let pk_bytes: [u8; 2592] = self
                    .raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid key length".into()))?;
                let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let sig_bytes: [u8; 4627] = signature
                    .raw()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid signature length".into()))?;
                if pk.verify(message, &sig_bytes, &[]) {
                    Ok(())
                } else {
                    Err(CesrError::VerificationFailed)
                }
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
        let (pad_bytes, code_str) = match self.code {
            SigningKeyCode::Secp256r1 => (3, "1AAJ"),
            SigningKeyCode::MlDsa65 => (1, "b"),
            SigningKeyCode::MlDsa87 => (3, "1AAK"),
        };
        let mut padded = vec![0u8; pad_bytes];
        padded.extend_from_slice(&self.raw);
        let encoded = b64_encode(&padded);
        format!("{}{}", code_str, &encoded[code_str.len()..])
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = SigningKeyCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let (pad_str, skip_bytes) = match code {
            SigningKeyCode::Secp256r1 => ("AAAA", 3usize),
            SigningKeyCode::MlDsa65 => ("A", 1usize),
            SigningKeyCode::MlDsa87 => ("AAAA", 3usize),
        };

        let to_decode = format!("{}{}", pad_str, &qb64[code.code_size()..]);
        let decoded = b64_decode(&to_decode)?;
        let raw = decoded[skip_bytes..].to_vec();

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
    /// ML-DSA-65 private key stored as 32-byte seed (deterministic keygen)
    MlDsa65([u8; 32]),
    /// ML-DSA-87 private key stored as 32-byte seed (deterministic keygen)
    MlDsa87([u8; 32]),
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
                    code: SigningKeyCode::Secp256r1,
                    raw,
                }
            }
            PrivateKey::MlDsa65(seed) => {
                let (pk, _sk) = ml_dsa_65::KG::keygen_from_seed(seed);
                let raw = pk.into_bytes().to_vec();
                PublicKey {
                    code: SigningKeyCode::MlDsa65,
                    raw,
                }
            }
            PrivateKey::MlDsa87(seed) => {
                let (pk, _sk) = ml_dsa_87::KG::keygen_from_seed(seed);
                let raw = pk.into_bytes().to_vec();
                PublicKey {
                    code: SigningKeyCode::MlDsa87,
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
            PrivateKey::MlDsa65(seed) => {
                let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(seed);
                let sig = sk
                    .try_sign(message, &[])
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Signature::from_raw(SignatureCode::MlDsa65, sig.to_vec())
            }
            PrivateKey::MlDsa87(seed) => {
                let (_pk, sk) = ml_dsa_87::KG::keygen_from_seed(seed);
                let sig = sk
                    .try_sign(message, &[])
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Signature::from_raw(SignatureCode::MlDsa87, sig.to_vec())
            }
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> SigningKeyCode {
        match self {
            PrivateKey::Secp256r1(_) => SigningKeyCode::Secp256r1,
            PrivateKey::MlDsa65(_) => SigningKeyCode::MlDsa65,
            PrivateKey::MlDsa87(_) => SigningKeyCode::MlDsa87,
        }
    }

    /// Export raw private key bytes (use with caution)
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Secp256r1(sk) => sk.to_bytes().to_vec(),
            PrivateKey::MlDsa65(seed) | PrivateKey::MlDsa87(seed) => seed.to_vec(),
        }
    }

    /// Import from raw bytes
    pub fn from_bytes(code: SigningKeyCode, bytes: &[u8]) -> Result<Self, CesrError> {
        match code {
            SigningKeyCode::Secp256r1 => {
                let sk = P256SigningKey::from_slice(bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Ok(PrivateKey::Secp256r1(sk))
            }
            SigningKeyCode::MlDsa65 => {
                let seed: [u8; 32] = bytes.try_into().map_err(|_| CesrError::InvalidLength {
                    expected: 32,
                    actual: bytes.len(),
                })?;
                Ok(PrivateKey::MlDsa65(seed))
            }
            SigningKeyCode::MlDsa87 => {
                let seed: [u8; 32] = bytes.try_into().map_err(|_| CesrError::InvalidLength {
                    expected: 32,
                    actual: bytes.len(),
                })?;
                Ok(PrivateKey::MlDsa87(seed))
            }
        }
    }

    /// Encode as qualified Base64 (qb64)
    pub fn qb64(&self) -> String {
        let raw = self.to_bytes();
        // All seeds are 32 bytes with 1-char codes
        // Prepend zero byte for alignment, encode, replace first char with code
        let mut padded = vec![0u8];
        padded.extend_from_slice(&raw);
        let encoded = b64_encode(&padded);
        let code = match self {
            PrivateKey::Secp256r1(_) => "Q",
            PrivateKey::MlDsa65(_) => "c",
            PrivateKey::MlDsa87(_) => "f",
        };
        format!("{}{}", code, &encoded[1..])
    }

    /// Decode from qualified Base64 (qb64)
    pub fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
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
            SeedCode::Secp256r1 => PrivateKey::from_bytes(SigningKeyCode::Secp256r1, &raw),
            SeedCode::MlDsa65 => PrivateKey::from_bytes(SigningKeyCode::MlDsa65, &raw),
            SeedCode::MlDsa87 => PrivateKey::from_bytes(SigningKeyCode::MlDsa87, &raw),
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKey::Secp256r1(_) => write!(f, "PrivateKey::Secp256r1([REDACTED])"),
            PrivateKey::MlDsa65(_) => write!(f, "PrivateKey::MlDsa65([REDACTED])"),
            PrivateKey::MlDsa87(_) => write!(f, "PrivateKey::MlDsa87([REDACTED])"),
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

/// Generate a new ML-DSA-65 key pair from a random 32-byte seed
pub fn generate_ml_dsa_65() -> Result<(PublicKey, PrivateKey), CesrError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let private = PrivateKey::MlDsa65(seed);
    let public = private.public_key();
    Ok((public, private))
}

/// Generate a new ML-DSA-87 key pair from a random 32-byte seed
pub fn generate_ml_dsa_87() -> Result<(PublicKey, PrivateKey), CesrError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let private = PrivateKey::MlDsa87(seed);
    let public = private.public_key();
    Ok((public, private))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256r1_generate() {
        let (public, private) = generate_secp256r1().unwrap();
        assert_eq!(public.algorithm(), SigningKeyCode::Secp256r1);
        assert_eq!(public.raw().len(), 33); // Compressed
        assert_eq!(private.algorithm(), SigningKeyCode::Secp256r1);
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

        let imported_private = PrivateKey::from_bytes(SigningKeyCode::Secp256r1, &bytes).unwrap();
        let imported_public = imported_private.public_key();

        assert_eq!(original_public, imported_public);
    }

    #[test]
    fn test_ml_dsa_65_generate() {
        let (public, private) = generate_ml_dsa_65().unwrap();
        assert_eq!(public.algorithm(), SigningKeyCode::MlDsa65);
        assert_eq!(public.raw().len(), 1952);
        assert_eq!(private.algorithm(), SigningKeyCode::MlDsa65);
    }

    #[test]
    fn test_ml_dsa_65_qb64() {
        let (public, _) = generate_ml_dsa_65().unwrap();
        let qb64 = public.qb64();
        assert!(qb64.starts_with('b'));
        assert_eq!(qb64.len(), 2604);

        let parsed = PublicKey::from_qb64(&qb64).unwrap();
        assert_eq!(public, parsed);
    }

    #[test]
    fn test_ml_dsa_65_sign_verify() {
        let (public, private) = generate_ml_dsa_65().unwrap();
        let message = b"Test message for ML-DSA-65 signing";

        let signature = private.sign(message).unwrap();
        assert!(public.verify(message, &signature).is_ok());
        assert!(public.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_ml_dsa_65_private_key_export_import() {
        let (original_public, original_private) = generate_ml_dsa_65().unwrap();
        let bytes = original_private.to_bytes();
        assert_eq!(bytes.len(), 32);

        let imported_private = PrivateKey::from_bytes(SigningKeyCode::MlDsa65, &bytes).unwrap();
        let imported_public = imported_private.public_key();

        assert_eq!(original_public, imported_public);
    }

    #[test]
    fn test_ml_dsa_65_private_key_qb64() {
        let (_, private) = generate_ml_dsa_65().unwrap();
        let qb64 = private.qb64();
        assert!(qb64.starts_with('c'));
        assert_eq!(qb64.len(), 44);

        let parsed = PrivateKey::from_qb64(&qb64).unwrap();
        assert_eq!(private.to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn test_ml_dsa_87_generate() {
        let (public, private) = generate_ml_dsa_87().unwrap();
        assert_eq!(public.algorithm(), SigningKeyCode::MlDsa87);
        assert_eq!(public.raw().len(), 2592);
        assert_eq!(private.algorithm(), SigningKeyCode::MlDsa87);
    }

    #[test]
    fn test_ml_dsa_87_qb64() {
        let (public, _) = generate_ml_dsa_87().unwrap();
        let qb64 = public.qb64();
        assert!(qb64.starts_with("1AAK"));
        assert_eq!(qb64.len(), 3460);

        let parsed = PublicKey::from_qb64(&qb64).unwrap();
        assert_eq!(public, parsed);
    }

    #[test]
    fn test_ml_dsa_87_sign_verify() {
        let (public, private) = generate_ml_dsa_87().unwrap();
        let message = b"Test message for ML-DSA-87 signing";

        let signature = private.sign(message).unwrap();
        assert!(public.verify(message, &signature).is_ok());
        assert!(public.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_ml_dsa_87_private_key_export_import() {
        let (original_public, original_private) = generate_ml_dsa_87().unwrap();
        let bytes = original_private.to_bytes();
        assert_eq!(bytes.len(), 32);

        let imported_private = PrivateKey::from_bytes(SigningKeyCode::MlDsa87, &bytes).unwrap();
        let imported_public = imported_private.public_key();

        assert_eq!(original_public, imported_public);
    }

    #[test]
    fn test_ml_dsa_87_private_key_qb64() {
        let (_, private) = generate_ml_dsa_87().unwrap();
        let qb64 = private.qb64();
        assert!(qb64.starts_with('f'));
        assert_eq!(qb64.len(), 44);

        let parsed = PrivateKey::from_qb64(&qb64).unwrap();
        assert_eq!(private.to_bytes(), parsed.to_bytes());
    }
}
