//! Cryptographic Keys
//!
//! CESR key primitives with support for:
//! - secp256r1: 33-byte compressed keys, 4-char code '1AAC' (33 % 3 == 0)
//! - ML-DSA-65: 1952-byte public keys, 1-char code 'Q' (1952 % 3 == 2)

use p256::ecdsa::{
    Signature as P256Sig, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::{Signer, Verifier},
};
use rand_core::{OsRng, RngCore};

use fips204::traits::{
    KeyGen as FipsKeyGen, SerDes as FipsSerDes, Signer as FipsSigner, Verifier as FipsVerifier,
};
use fips204::{ml_dsa_65, ml_dsa_87};

use crate::base64::{b64_decode, b64_encode};
use crate::codes::{SignatureCode, SigningKeySeedCode, VerificationKeyCode};
use crate::error::CesrError;
use crate::matter::Matter;
use crate::signature::Signature;

/// A public key with CESR encoding
#[derive(Debug, Clone)]
pub struct VerificationKey {
    code: VerificationKeyCode,
    raw: Vec<u8>,
}

impl VerificationKey {
    /// Create from raw bytes with specified algorithm
    pub fn from_raw(code: VerificationKeyCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        // Validate the key can be parsed
        match code {
            VerificationKeyCode::Secp256r1 => {
                if raw.len() != 33 {
                    return Err(CesrError::InvalidLength {
                        expected: 33,
                        actual: raw.len(),
                    });
                }
                P256VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
            }
            VerificationKeyCode::MlDsa65 => {
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
            VerificationKeyCode::MlDsa87 => {
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
        Ok(VerificationKey { code, raw })
    }

    /// Get the key algorithm
    pub fn algorithm(&self) -> VerificationKeyCode {
        self.code
    }

    /// Verify a signature over a message
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CesrError> {
        match self.code {
            VerificationKeyCode::Secp256r1 => {
                let verifying_key = P256VerifyingKey::from_sec1_bytes(&self.raw)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let sig = P256Sig::from_slice(signature.raw())
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| CesrError::VerificationFailed)
            }
            VerificationKeyCode::MlDsa65 => {
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
            VerificationKeyCode::MlDsa87 => {
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

impl Matter for VerificationKey {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        let (pad_bytes, code_str) = match self.code {
            VerificationKeyCode::Secp256r1 => (3, "1AAC"),
            VerificationKeyCode::MlDsa65 => (1, "Q"),
            VerificationKeyCode::MlDsa87 => (3, "1AAU"),
        };
        let mut padded = vec![0u8; pad_bytes];
        padded.extend_from_slice(&self.raw);
        let encoded = b64_encode(&padded);
        format!("{}{}", code_str, &encoded[code_str.len()..])
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = VerificationKeyCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let (pad_str, skip_bytes) = match code {
            VerificationKeyCode::Secp256r1 => ("AAAA", 3usize),
            VerificationKeyCode::MlDsa65 => ("A", 1usize),
            VerificationKeyCode::MlDsa87 => ("AAAA", 3usize),
        };

        let to_decode = format!("{}{}", pad_str, &qb64[code.code_size()..]);
        let decoded = b64_decode(&to_decode)?;
        let raw = decoded[skip_bytes..].to_vec();

        VerificationKey::from_raw(code, raw)
    }
}

impl PartialEq for VerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.raw == other.raw
    }
}

impl Eq for VerificationKey {}

impl PartialOrd for VerificationKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerificationKey {
    /// Compare by qb64 representation, computed inline. Mirrors
    /// `Digest256` and the nonce types so all CESR primitives share one
    /// ordering semantics (qb64 canonical identity, byte-equal to
    /// PostgreSQL TEXT collation). `VerificationKey` does not cache its
    /// qb64 because ML-DSA-87 keys are ~2.5 KB; the inline conversion at
    /// comparison time is the trade-off for keeping ordering consistent
    /// without the per-instance cache cost.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use crate::matter::Matter;
        self.qb64().cmp(&other.qb64())
    }
}

impl std::hash::Hash for VerificationKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state);
        self.raw.hash(state);
    }
}

impl std::fmt::Display for VerificationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for VerificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
    }
}

impl<'de> serde::Deserialize<'de> for VerificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        VerificationKey::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

/// A private key for signing (not CESR-encoded for security)
#[derive(Clone)]
pub enum SigningKey {
    Secp256r1(P256SigningKey),
    /// ML-DSA-65 private key stored as 32-byte seed (deterministic keygen)
    MlDsa65([u8; 32]),
    /// ML-DSA-87 private key stored as 32-byte seed (deterministic keygen)
    MlDsa87([u8; 32]),
}

impl SigningKey {
    /// Get the corresponding public key
    pub fn verification_key(&self) -> VerificationKey {
        match self {
            SigningKey::Secp256r1(sk) => {
                let vk = sk.verifying_key();
                // Compressed SEC1 encoding
                let raw = vk.to_encoded_point(true).as_bytes().to_vec();
                VerificationKey {
                    code: VerificationKeyCode::Secp256r1,
                    raw,
                }
            }
            SigningKey::MlDsa65(seed) => {
                let (pk, _sk) = ml_dsa_65::KG::keygen_from_seed(seed);
                let raw = pk.into_bytes().to_vec();
                VerificationKey {
                    code: VerificationKeyCode::MlDsa65,
                    raw,
                }
            }
            SigningKey::MlDsa87(seed) => {
                let (pk, _sk) = ml_dsa_87::KG::keygen_from_seed(seed);
                let raw = pk.into_bytes().to_vec();
                VerificationKey {
                    code: VerificationKeyCode::MlDsa87,
                    raw,
                }
            }
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Signature, CesrError> {
        match self {
            SigningKey::Secp256r1(sk) => {
                let sig: P256Sig = sk.sign(message);
                Signature::from_raw(SignatureCode::Secp256r1, sig.to_bytes().to_vec())
            }
            SigningKey::MlDsa65(seed) => {
                let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(seed);
                let sig = sk
                    .try_sign(message, &[])
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Signature::from_raw(SignatureCode::MlDsa65, sig.to_vec())
            }
            SigningKey::MlDsa87(seed) => {
                let (_pk, sk) = ml_dsa_87::KG::keygen_from_seed(seed);
                let sig = sk
                    .try_sign(message, &[])
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Signature::from_raw(SignatureCode::MlDsa87, sig.to_vec())
            }
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> VerificationKeyCode {
        match self {
            SigningKey::Secp256r1(_) => VerificationKeyCode::Secp256r1,
            SigningKey::MlDsa65(_) => VerificationKeyCode::MlDsa65,
            SigningKey::MlDsa87(_) => VerificationKeyCode::MlDsa87,
        }
    }

    /// Export raw private key bytes (use with caution)
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Secp256r1(sk) => sk.to_bytes().to_vec(),
            SigningKey::MlDsa65(seed) | SigningKey::MlDsa87(seed) => seed.to_vec(),
        }
    }

    /// Import from raw bytes
    pub fn from_bytes(code: VerificationKeyCode, bytes: &[u8]) -> Result<Self, CesrError> {
        match code {
            VerificationKeyCode::Secp256r1 => {
                let sk = P256SigningKey::from_slice(bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Ok(SigningKey::Secp256r1(sk))
            }
            VerificationKeyCode::MlDsa65 => {
                let seed: [u8; 32] = bytes.try_into().map_err(|_| CesrError::InvalidLength {
                    expected: 32,
                    actual: bytes.len(),
                })?;
                Ok(SigningKey::MlDsa65(seed))
            }
            VerificationKeyCode::MlDsa87 => {
                let seed: [u8; 32] = bytes.try_into().map_err(|_| CesrError::InvalidLength {
                    expected: 32,
                    actual: bytes.len(),
                })?;
                Ok(SigningKey::MlDsa87(seed))
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
            SigningKey::Secp256r1(_) => "c",
            SigningKey::MlDsa65(_) => "q",
            SigningKey::MlDsa87(_) => "u",
        };
        format!("{}{}", code, &encoded[1..])
    }

    /// Decode from qualified Base64 (qb64)
    pub fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = SigningKeySeedCode::detect(qb64)?;

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
            SigningKeySeedCode::Secp256r1 => {
                SigningKey::from_bytes(VerificationKeyCode::Secp256r1, &raw)
            }
            SigningKeySeedCode::MlDsa65 => {
                SigningKey::from_bytes(VerificationKeyCode::MlDsa65, &raw)
            }
            SigningKeySeedCode::MlDsa87 => {
                SigningKey::from_bytes(VerificationKeyCode::MlDsa87, &raw)
            }
        }
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningKey::Secp256r1(_) => write!(f, "SigningKey::Secp256r1([REDACTED])"),
            SigningKey::MlDsa65(_) => write!(f, "SigningKey::MlDsa65([REDACTED])"),
            SigningKey::MlDsa87(_) => write!(f, "SigningKey::MlDsa87([REDACTED])"),
        }
    }
}

/// Generate a new secp256r1 (P-256) key pair
pub fn generate_secp256r1() -> Result<(VerificationKey, SigningKey), CesrError> {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let private = SigningKey::Secp256r1(signing_key);
    let public = private.verification_key();
    Ok((public, private))
}

/// Generate a new ML-DSA-65 key pair from a random 32-byte seed
pub fn generate_ml_dsa_65() -> Result<(VerificationKey, SigningKey), CesrError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let private = SigningKey::MlDsa65(seed);
    let public = private.verification_key();
    Ok((public, private))
}

/// Generate a new ML-DSA-87 key pair from a random 32-byte seed
pub fn generate_ml_dsa_87() -> Result<(VerificationKey, SigningKey), CesrError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let private = SigningKey::MlDsa87(seed);
    let public = private.verification_key();
    Ok((public, private))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256r1_generate() {
        let (public, private) = generate_secp256r1().unwrap();
        assert_eq!(public.algorithm(), VerificationKeyCode::Secp256r1);
        assert_eq!(public.raw().len(), 33); // Compressed
        assert_eq!(private.algorithm(), VerificationKeyCode::Secp256r1);
    }

    #[test]
    fn test_secp256r1_qb64() {
        let (public, _) = generate_secp256r1().unwrap();
        let qb64 = public.qb64();
        assert!(qb64.starts_with("1AAC"));
        assert_eq!(qb64.len(), 48);

        let parsed = VerificationKey::from_qb64(&qb64).unwrap();
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

        let imported_private =
            SigningKey::from_bytes(VerificationKeyCode::Secp256r1, &bytes).unwrap();
        let imported_public = imported_private.verification_key();

        assert_eq!(original_public, imported_public);
    }

    #[test]
    fn test_ml_dsa_65_generate() {
        let (public, private) = generate_ml_dsa_65().unwrap();
        assert_eq!(public.algorithm(), VerificationKeyCode::MlDsa65);
        assert_eq!(public.raw().len(), 1952);
        assert_eq!(private.algorithm(), VerificationKeyCode::MlDsa65);
    }

    #[test]
    fn test_ml_dsa_65_qb64() {
        let (public, _) = generate_ml_dsa_65().unwrap();
        let qb64 = public.qb64();
        assert!(qb64.starts_with('Q'));
        assert_eq!(qb64.len(), 2604);

        let parsed = VerificationKey::from_qb64(&qb64).unwrap();
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

        let imported_private =
            SigningKey::from_bytes(VerificationKeyCode::MlDsa65, &bytes).unwrap();
        let imported_public = imported_private.verification_key();

        assert_eq!(original_public, imported_public);
    }

    #[test]
    fn test_ml_dsa_65_private_key_qb64() {
        let (_, private) = generate_ml_dsa_65().unwrap();
        let qb64 = private.qb64();
        assert!(qb64.starts_with('q'));
        assert_eq!(qb64.len(), 44);

        let parsed = SigningKey::from_qb64(&qb64).unwrap();
        assert_eq!(private.to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn test_ml_dsa_87_generate() {
        let (public, private) = generate_ml_dsa_87().unwrap();
        assert_eq!(public.algorithm(), VerificationKeyCode::MlDsa87);
        assert_eq!(public.raw().len(), 2592);
        assert_eq!(private.algorithm(), VerificationKeyCode::MlDsa87);
    }

    #[test]
    fn test_ml_dsa_87_qb64() {
        let (public, _) = generate_ml_dsa_87().unwrap();
        let qb64 = public.qb64();
        assert!(qb64.starts_with("1AAU"));
        assert_eq!(qb64.len(), 3460);

        let parsed = VerificationKey::from_qb64(&qb64).unwrap();
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

        let imported_private =
            SigningKey::from_bytes(VerificationKeyCode::MlDsa87, &bytes).unwrap();
        let imported_public = imported_private.verification_key();

        assert_eq!(original_public, imported_public);
    }

    #[test]
    fn test_ml_dsa_87_private_key_qb64() {
        let (_, private) = generate_ml_dsa_87().unwrap();
        let qb64 = private.qb64();
        assert!(qb64.starts_with('u'));
        assert_eq!(qb64.len(), 44);

        let parsed = SigningKey::from_qb64(&qb64).unwrap();
        assert_eq!(private.to_bytes(), parsed.to_bytes());
    }
}
