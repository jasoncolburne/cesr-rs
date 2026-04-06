//! Cryptographic Digests
//!
//! CESR digests are self-describing hash outputs.
//! Code length is chosen to avoid Base64 padding:
//! - 32 bytes (256 bits): 32 % 3 == 2, needs 1 padding char → 1-char code

use crate::base64::{b64_decode, b64_encode};
use crate::codes::DigestCode;
use crate::error::CesrError;
use crate::matter::Matter;

/// A cryptographic digest with CESR encoding
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    code: DigestCode,
    raw: Vec<u8>,
}

/// Blake3 hash of empty input, used as the default digest.
const EMPTY_BLAKE3_RAW: [u8; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

impl Default for Digest {
    fn default() -> Self {
        Digest {
            code: DigestCode::Blake3,
            raw: EMPTY_BLAKE3_RAW.to_vec(),
        }
    }
}

impl Digest {
    /// Create a Blake3-256 digest of the given data
    pub fn blake3_256(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Digest {
            code: DigestCode::Blake3,
            raw: hash.as_bytes().to_vec(),
        }
    }

    /// Create a digest from raw bytes with specified algorithm
    pub fn from_raw(code: DigestCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }
        Ok(Digest { code, raw })
    }

    /// Get the digest algorithm
    pub fn algorithm(&self) -> DigestCode {
        self.code
    }

    /// Compare this digest to the hash of some data
    pub fn verify(&self, data: &[u8]) -> bool {
        match self.code {
            DigestCode::Blake3 => {
                let computed = blake3::hash(data);
                self.raw == computed.as_bytes()
            }
        }
    }
}

impl Matter for Digest {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        // For 1-char codes with 32-byte raw:
        // We need to handle the alignment properly
        // 32 bytes = 256 bits, in base64 = 43 chars (with 2 bits unused)
        // The code char uses those 2 bits, so we prepend 2 zero bits to raw
        // and encode (code_bits || raw) together

        // Simpler approach for 1-char codes:
        // Prepend a zero byte, encode, replace first char with code
        let mut padded = vec![0u8];
        padded.extend_from_slice(&self.raw);
        let encoded = b64_encode(&padded);
        // Replace first char with code
        format!("{}{}", self.code.code(), &encoded[1..])
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        if qb64.is_empty() {
            return Err(CesrError::ParseError("Empty qb64 string".to_string()));
        }

        // Detect code from first character(s)
        let code = DigestCode::from_code(&qb64[..1])?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        // Decode: replace code with 'A' (zero bits) and decode
        let to_decode = format!("A{}", &qb64[1..]);
        let decoded = b64_decode(&to_decode)?;

        // Skip the padding byte
        let raw = decoded[1..].to_vec();

        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }

        Ok(Digest { code, raw })
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Digest::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_256() {
        let data = b"Hello, CESR!";
        let digest = Digest::blake3_256(data);

        assert_eq!(digest.algorithm(), DigestCode::Blake3);
        assert_eq!(digest.raw().len(), 32);
        assert!(digest.verify(data));
        assert!(!digest.verify(b"Different data"));
    }

    #[test]
    fn test_qb64_roundtrip() {
        let data = b"Test data for hashing";
        let digest = Digest::blake3_256(data);

        let qb64 = digest.qb64();
        assert!(qb64.starts_with('K'));
        assert_eq!(qb64.len(), 44);

        let parsed = Digest::from_qb64(&qb64).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn test_default_is_blake3_of_empty() {
        let default = Digest::default();
        let empty_hash = Digest::blake3_256(b"");
        assert_eq!(default, empty_hash);
        assert_eq!(
            default.qb64(),
            "KK8TSbn1-aGmoEBN6jbcyUmbyyXJrcESt8yak8rkHzJi"
        );
    }

    #[test]
    fn test_hash_impl() {
        use std::collections::HashSet;
        let d1 = Digest::blake3_256(b"hello");
        let d2 = Digest::blake3_256(b"hello");
        let d3 = Digest::blake3_256(b"world");
        let mut set = HashSet::new();
        set.insert(d1.clone());
        assert!(set.contains(&d2));
        assert!(!set.contains(&d3));
    }

    #[test]
    fn test_deterministic() {
        let data = b"Same input";
        let d1 = Digest::blake3_256(data);
        let d2 = Digest::blake3_256(data);
        assert_eq!(d1, d2);
        assert_eq!(d1.qb64(), d2.qb64());
    }
}
