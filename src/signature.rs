//! Cryptographic Signatures
//!
//! CESR signature primitives:
//! - secp256r1: 64-byte signatures, 2-char code '0I' (64 % 3 == 1)
//! - ML-DSA-65: 3309-byte signatures, 4-char code '1AAQ' (3309 % 3 == 0)

use crate::base64::{b64_decode, b64_encode};
use crate::codes::SignatureCode;
use crate::error::CesrError;
use crate::matter::Matter;

/// A cryptographic signature with CESR encoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    code: SignatureCode,
    raw: Vec<u8>,
}

impl Signature {
    /// Create from raw bytes with specified algorithm
    pub fn from_raw(code: SignatureCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }
        Ok(Signature { code, raw })
    }

    /// Get the signature algorithm
    pub fn algorithm(&self) -> SignatureCode {
        self.code
    }
}

impl Matter for Signature {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        match self.code {
            SignatureCode::Secp256r1 => {
                // 64 bytes, 2-char code '0I'
                // Prepend 2 zero bytes, encode, replace first 2 chars with code
                let mut padded = vec![0u8; 2];
                padded.extend_from_slice(&self.raw);
                let encoded = b64_encode(&padded);
                format!("{}{}", self.code.code(), &encoded[2..])
            }
            SignatureCode::MlDsa65 => {
                // 3309 bytes, 4-char code '1AAQ'
                // 3309 % 3 == 0, so 3 pad bytes for 4-char code
                // Prepend 3 zero bytes, encode, replace first 4 chars with code
                let mut padded = vec![0u8; 3];
                padded.extend_from_slice(&self.raw);
                let encoded = b64_encode(&padded);
                format!("{}{}", self.code.code(), &encoded[4..])
            }
        }
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = SignatureCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let (pad_str, skip_bytes) = match code {
            SignatureCode::Secp256r1 => ("AA", 2usize),
            SignatureCode::MlDsa65 => ("AAAA", 3usize),
        };

        let to_decode = format!("{}{}", pad_str, &qb64[code.code_size()..]);
        let decoded = b64_decode(&to_decode)?;
        let raw = decoded[skip_bytes..].to_vec();

        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }

        Ok(Signature { code, raw })
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_ml_dsa_65, generate_secp256r1};

    #[test]
    fn test_secp256r1_signature_qb64() {
        let (_, private) = generate_secp256r1().unwrap();
        let sig = private.sign(b"test message").unwrap();

        let qb64 = sig.qb64();
        assert!(qb64.starts_with("0I"));
        assert_eq!(qb64.len(), 88);

        let parsed = Signature::from_qb64(&qb64).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn test_ml_dsa_65_signature_qb64() {
        let (_, private) = generate_ml_dsa_65().unwrap();
        let sig = private.sign(b"test message").unwrap();

        let qb64 = sig.qb64();
        assert!(qb64.starts_with("1AAQ"));
        assert_eq!(qb64.len(), 4416);

        let parsed = Signature::from_qb64(&qb64).unwrap();
        assert_eq!(sig, parsed);
    }
}
