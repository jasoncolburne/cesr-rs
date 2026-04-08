//! Cryptographic Digests
//!
//! CESR digests are self-describing hash outputs.
//! Code length is chosen to avoid Base64 padding:
//! - 32 bytes (256 bits): 32 % 3 == 2, needs 1 padding char → 1-char code

use crate::base64::{b64_decode, b64_encode};
use crate::codes::DigestCode;
use crate::error::CesrError;
use crate::matter::Matter;

/// A cryptographic digest with CESR encoding.
///
/// Unlike other CESR types, `Digest` caches its qb64 representation on construction
/// for zero-allocation `&str` access via `AsRef<str>`. This is worthwhile because
/// digests are small (44 chars for Blake3-256), ubiquitous (every self-addressed struct
/// has at least one), and frequently need string access for cache keys, logging, and
/// comparisons. Larger types like `Signature` and `VerificationKey` compute qb64 on
/// demand since their encoded forms can be several kilobytes and string access is
/// infrequent outside serialization.
#[derive(Debug, Clone)]
pub struct Digest {
    code: DigestCode,
    raw: Vec<u8>,
    qb64: String,
}

/// Compute the qb64 string from code and raw bytes.
fn compute_qb64(code: DigestCode, raw: &[u8]) -> String {
    let mut padded = vec![0u8];
    padded.extend_from_slice(raw);
    let encoded = b64_encode(&padded);
    format!("{}{}", code.code(), &encoded[1..])
}

// Manual trait impls that ignore the cached qb64 field

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.raw == other.raw
    }
}

impl Eq for Digest {}

impl std::hash::Hash for Digest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state);
        self.raw.hash(state);
    }
}

impl PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Digest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.code.cmp(&other.code).then(self.raw.cmp(&other.raw))
    }
}

/// Blake3 hash of empty input, used as the default digest.
const EMPTY_BLAKE3_RAW: [u8; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

impl Default for Digest {
    fn default() -> Self {
        let code = DigestCode::Blake3;
        let raw = EMPTY_BLAKE3_RAW.to_vec();
        let qb64 = compute_qb64(code, &raw);
        Digest { code, raw, qb64 }
    }
}

impl Digest {
    /// Create a Blake3-256 digest of the given data
    pub fn blake3_256(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        let code = DigestCode::Blake3;
        let raw = hash.as_bytes().to_vec();
        let qb64 = compute_qb64(code, &raw);
        Digest { code, raw, qb64 }
    }

    /// Create a digest from raw bytes with specified algorithm
    pub fn from_raw(code: DigestCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }
        let qb64 = compute_qb64(code, &raw);
        Ok(Digest { code, raw, qb64 })
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

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        &self.qb64
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
        self.qb64.clone()
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

        Ok(Digest {
            code,
            raw,
            qb64: qb64.to_string(),
        })
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.qb64)
    }
}

impl serde::Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64)
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

/// Create a human-readable test digest from a tag string.
///
/// Produces a valid 44-character CESR digest like `Kmy_tag_____________________________________`
/// that is immediately recognizable in test output. The digest is syntactically valid
/// but not derivable from any input — use `Digest::blake3_256()` when you need a real hash.
///
/// # Panics
///
/// Panics if `tag` is longer than 42 characters or contains non-base64url characters.
#[cfg(feature = "test-utils")]
pub fn test_digest(tag: &str) -> Digest {
    assert!(
        tag.len() <= 43,
        "test_digest tag must be <= 43 characters, got {}",
        tag.len()
    );
    let qb64 = format!("K{}{}", tag, "_".repeat(43 - tag.len()));
    Digest::from_qb64(&qb64).unwrap_or_else(|e| panic!("invalid test_digest tag '{tag}': {e}"))
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
    fn test_as_ref_str() {
        let digest = Digest::blake3_256(b"test");
        let s: &str = digest.as_ref();
        assert_eq!(s, digest.qb64());
        assert!(s.starts_with('K'));
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
