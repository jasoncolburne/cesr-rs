//! Cryptographic Digests
//!
//! CESR digests are self-describing hash outputs.
//! Code length is chosen to avoid Base64 padding:
//! - 32 bytes (256 bits): 32 % 3 == 2, needs 1 padding char → 1-char code

use crate::base64::{b64_decode, b64_encode};
use crate::codes::Digest256Code;
use crate::error::CesrError;
use crate::matter::Matter;

/// A cryptographic digest with CESR encoding.
///
/// Fixed-size representation: 32 bytes raw + 44 bytes QB64 cache. This enables `Copy`
/// semantics, which is important for use as map keys, gossip peer identifiers, and
/// general value passing without allocation. If additional digest sizes are needed
/// in the future, introduce `Digest384`/`Digest512` types.
#[derive(Debug, Clone, Copy)]
pub struct Digest256 {
    code: Digest256Code,
    raw: [u8; 32],
    qb64b: [u8; 44],
}

/// Compute the qb64 bytes from code and raw bytes.
fn compute_qb64(code: Digest256Code, raw: &[u8; 32]) -> [u8; 44] {
    let mut padded = vec![0u8];
    padded.extend_from_slice(raw);
    let encoded = b64_encode(&padded);
    let qb64_str = format!("{}{}", code.code(), &encoded[1..]);
    let mut qb64 = [0u8; 44];
    qb64.copy_from_slice(qb64_str.as_bytes());
    qb64
}

// Manual trait impls that ignore the cached qb64 field

impl PartialEq for Digest256 {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.raw == other.raw
    }
}

impl Eq for Digest256 {}

impl std::hash::Hash for Digest256 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state);
        self.raw.hash(state);
    }
}

impl PartialOrd for Digest256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Digest256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.code.cmp(&other.code).then(self.raw.cmp(&other.raw))
    }
}

/// Blake3 hash of empty input, used as the default digest.
const EMPTY_BLAKE3_RAW: [u8; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

impl Default for Digest256 {
    fn default() -> Self {
        let code = Digest256Code::Blake3;
        let qb64 = compute_qb64(code, &EMPTY_BLAKE3_RAW);
        Digest256 {
            code,
            raw: EMPTY_BLAKE3_RAW,
            qb64b: qb64,
        }
    }
}

impl Digest256 {
    /// Create a Blake3-256 digest of the given data
    pub fn blake3_256(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        let code = Digest256Code::Blake3;
        let raw = *hash.as_bytes();
        let qb64 = compute_qb64(code, &raw);
        Digest256 {
            code,
            raw,
            qb64b: qb64,
        }
    }

    /// Create a digest from raw bytes with specified algorithm
    pub fn from_raw(code: Digest256Code, raw: Vec<u8>) -> Result<Self, CesrError> {
        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }
        let mut raw_arr = [0u8; 32];
        raw_arr.copy_from_slice(&raw);
        let qb64 = compute_qb64(code, &raw_arr);
        Ok(Digest256 {
            code,
            raw: raw_arr,
            qb64b: qb64,
        })
    }

    /// Get the QB64 representation as raw bytes.
    pub fn qb64b(&self) -> &[u8; 44] {
        &self.qb64b
    }

    /// Create a digest from QB64 bytes (44-byte array).
    pub fn from_qb64b(qb64: [u8; 44]) -> Result<Self, CesrError> {
        let s = std::str::from_utf8(&qb64)
            .map_err(|e| CesrError::ParseError(format!("Invalid UTF-8 in qb64 bytes: {e}")))?;
        Self::from_qb64(s)
    }

    /// Get the digest algorithm
    pub fn algorithm(&self) -> Digest256Code {
        self.code
    }

    /// Compare this digest to the hash of some data
    pub fn verify(&self, data: &[u8]) -> bool {
        match self.code {
            Digest256Code::Blake3 => {
                let computed = blake3::hash(data);
                self.raw == *computed.as_bytes()
            }
        }
    }
}

impl AsRef<str> for Digest256 {
    fn as_ref(&self) -> &str {
        // Safety: qb64 is always valid UTF-8 (ASCII base64url characters)
        std::str::from_utf8(&self.qb64b).unwrap_or("")
    }
}

impl Matter for Digest256 {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        String::from_utf8_lossy(&self.qb64b).into_owned()
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        if qb64.is_empty() {
            return Err(CesrError::ParseError("Empty qb64 string".to_string()));
        }

        // Detect code from first character(s)
        let code = Digest256Code::from_code(&qb64[..1])?;

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
        if decoded.len() - 1 != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: decoded.len() - 1,
            });
        }

        let mut raw = [0u8; 32];
        raw.copy_from_slice(&decoded[1..]);

        let mut qb64_arr = [0u8; 44];
        qb64_arr.copy_from_slice(qb64.as_bytes());

        Ok(Digest256 {
            code,
            raw,
            qb64b: qb64_arr,
        })
    }
}

impl std::fmt::Display for Digest256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl serde::Serialize for Digest256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for Digest256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Digest256::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

/// Create a human-readable test digest from a tag string.
///
/// Produces a valid 44-character CESR digest like `Kmy-tag_____________________________________`
/// that is immediately recognizable in test output. The digest is syntactically valid
/// but not derivable from any input — use `Digest::blake3_256()` when you need a real hash.
///
/// # Panics
///
/// Panics if `tag` is longer than 43 characters or contains non-base64url characters.
#[cfg(feature = "test-utils")]
pub fn test_digest(tag: &str) -> Digest256 {
    assert!(
        tag.len() <= 43,
        "test_digest tag must be <= 43 characters, got {}",
        tag.len()
    );
    let qb64 = format!("K{}{}", tag, "_".repeat(43 - tag.len()));
    Digest256::from_qb64(&qb64).unwrap_or_else(|e| panic!("invalid test_digest tag '{tag}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_256() {
        let data = b"Hello, CESR!";
        let digest = Digest256::blake3_256(data);

        assert_eq!(digest.algorithm(), Digest256Code::Blake3);
        assert_eq!(digest.raw().len(), 32);
        assert!(digest.verify(data));
        assert!(!digest.verify(b"Different data"));
    }

    #[test]
    fn test_qb64_roundtrip() {
        let data = b"Test data for hashing";
        let digest = Digest256::blake3_256(data);

        let qb64 = digest.qb64();
        assert!(qb64.starts_with('K'));
        assert_eq!(qb64.len(), 44);

        let parsed = Digest256::from_qb64(&qb64).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn test_default_is_blake3_of_empty() {
        let default = Digest256::default();
        let empty_hash = Digest256::blake3_256(b"");
        assert_eq!(default, empty_hash);
        assert_eq!(
            default.qb64(),
            "KK8TSbn1-aGmoEBN6jbcyUmbyyXJrcESt8yak8rkHzJi"
        );
    }

    #[test]
    fn test_as_ref_str() {
        let digest = Digest256::blake3_256(b"test");
        let s: &str = digest.as_ref();
        assert_eq!(s, digest.qb64());
        assert!(s.starts_with('K'));
    }

    #[test]
    fn test_hash_impl() {
        use std::collections::HashSet;
        let d1 = Digest256::blake3_256(b"hello");
        let d2 = Digest256::blake3_256(b"hello");
        let d3 = Digest256::blake3_256(b"world");
        let mut set = HashSet::new();
        set.insert(d1);
        assert!(set.contains(&d2));
        assert!(!set.contains(&d3));
    }

    #[test]
    fn test_deterministic() {
        let data = b"Same input";
        let d1 = Digest256::blake3_256(data);
        let d2 = Digest256::blake3_256(data);
        assert_eq!(d1, d2);
        assert_eq!(d1.qb64(), d2.qb64());
    }

    #[test]
    fn test_copy() {
        let d1 = Digest256::blake3_256(b"copy test");
        let d2 = d1; // Copy, not move
        assert_eq!(d1, d2); // d1 still usable
    }
}
