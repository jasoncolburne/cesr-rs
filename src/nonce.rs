//! CESR Nonce primitives

use crate::base64::{b64_decode, b64_encode};
use crate::codes::{Nonce96Code, Nonce256Code};
use crate::error::CesrError;
use crate::matter::Matter;

/// A CESR-encoded nonce.
#[derive(Debug, Clone, Copy)]
pub struct Nonce96 {
    code: Nonce96Code,
    raw: [u8; 12],
    qb64b: [u8; 20],
}

/// Compute the qb64 bytes from code and raw bytes.
fn compute_96_qb64b(code: Nonce96Code, raw: &[u8; 12]) -> [u8; 20] {
    // 12 bytes is evenly divisible by 3, so no padding needed
    let encoded = b64_encode(raw);
    let qb64 = format!("{}{}", code.code(), &encoded);
    let mut qb64b = [0u8; 20];
    qb64b.copy_from_slice(qb64.as_bytes());
    qb64b
}

impl PartialEq for Nonce96 {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.raw == other.raw
    }
}

impl Eq for Nonce96 {}

impl std::hash::Hash for Nonce96 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state);
        self.raw.hash(state);
    }
}

impl PartialOrd for Nonce96 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Nonce96 {
    /// Compare by qb64 representation. See `Digest256::cmp` for the full
    /// rationale.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.qb64b.cmp(&other.qb64b)
    }
}

impl Default for Nonce96 {
    fn default() -> Self {
        let code = Nonce96Code::AesGcm256;
        let raw = [0u8; 12];
        let qb64b = compute_96_qb64b(code, &raw);
        Nonce96 { code, raw, qb64b }
    }
}

impl Nonce96 {
    /// Create from raw 12-byte nonce.
    pub fn new(raw: [u8; 12]) -> Self {
        let code = Nonce96Code::AesGcm256;
        let qb64b = compute_96_qb64b(code, &raw);

        Nonce96 { code, raw, qb64b }
    }

    /// Generate a random nonce.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut raw = [0u8; 12];
        OsRng.fill_bytes(&mut raw);
        Self::new(raw)
    }

    /// Get the raw bytes as a fixed-size array.
    pub fn to_bytes(&self) -> [u8; 12] {
        self.raw
    }
}

impl AsRef<str> for Nonce96 {
    fn as_ref(&self) -> &str {
        // Safety: qb64 is always valid UTF-8 (ASCII base64url characters)
        std::str::from_utf8(&self.qb64b).unwrap_or("")
    }
}

impl Matter for Nonce96 {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        self.as_ref().to_owned()
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = Nonce96Code::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let decoded = b64_decode(&qb64[4..])?;
        let raw: [u8; 12] = decoded
            .try_into()
            .map_err(|_| CesrError::CryptoError("invalid nonce length".into()))?;
        let mut qb64b = [0u8; 20];
        qb64b.copy_from_slice(qb64.as_bytes());

        Ok(Nonce96 { code, raw, qb64b })
    }
}

impl std::fmt::Display for Nonce96 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl serde::Serialize for Nonce96 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for Nonce96 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Nonce96::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

/// A CESR-encoded 256-bit nonce.
#[derive(Debug, Clone, Copy)]
pub struct Nonce256 {
    code: Nonce256Code,
    raw: [u8; 32],
    qb64b: [u8; 44],
}

/// Compute the qb64 bytes from code and raw bytes.
fn compute_256_qb64b(code: Nonce256Code, raw: &[u8; 32]) -> [u8; 44] {
    let mut padded = vec![0u8];
    padded.extend_from_slice(raw);
    let encoded = b64_encode(&padded);
    let qb64 = format!("{}{}", code.code(), &encoded[1..]);
    let mut qb64b = [0u8; 44];
    qb64b.copy_from_slice(qb64.as_bytes());
    qb64b
}

impl PartialEq for Nonce256 {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.raw == other.raw
    }
}

impl Eq for Nonce256 {}

impl std::hash::Hash for Nonce256 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state);
        self.raw.hash(state);
    }
}

impl PartialOrd for Nonce256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Nonce256 {
    /// Compare by qb64 representation. See `Digest256::cmp` for the full
    /// rationale.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.qb64b.cmp(&other.qb64b)
    }
}

impl Default for Nonce256 {
    fn default() -> Self {
        let code = Nonce256Code::Random;
        let raw = [0u8; 32];
        let qb64b = compute_256_qb64b(code, &raw);
        Nonce256 { code, raw, qb64b }
    }
}

impl Nonce256 {
    /// Create from raw 32-byte nonce.
    pub fn new(raw: [u8; 32]) -> Self {
        let code = Nonce256Code::Random;
        let qb64b = compute_256_qb64b(code, &raw);

        Nonce256 { code, raw, qb64b }
    }

    /// Generate a random nonce.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        Self::new(raw)
    }

    /// Get the raw bytes as a fixed-size array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.raw
    }
}

impl AsRef<str> for Nonce256 {
    fn as_ref(&self) -> &str {
        // Safety: qb64 is always valid UTF-8 (ASCII base64url characters)
        std::str::from_utf8(&self.qb64b).unwrap_or("")
    }
}

impl Matter for Nonce256 {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        self.as_ref().to_owned()
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = Nonce256Code::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        // Decode: replace 1-char code with 'A' (zero pad) then decode all 44 chars
        let b64_payload = format!("A{}", &qb64[1..]);
        let decoded = b64_decode(&b64_payload)?;
        // First byte is padding, rest is raw
        let raw: [u8; 32] = decoded[1..]
            .try_into()
            .map_err(|_| CesrError::CryptoError("invalid nonce length".into()))?;
        let mut qb64b = [0u8; 44];
        qb64b.copy_from_slice(qb64.as_bytes());

        Ok(Nonce256 { code, raw, qb64b })
    }
}

impl std::fmt::Display for Nonce256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl serde::Serialize for Nonce256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for Nonce256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Nonce256::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_roundtrip() {
        let nonce = Nonce96::generate();
        let qb64 = nonce.qb64();
        assert!(qb64.starts_with("1AAN"));
        assert_eq!(qb64.len(), 20);

        let parsed = Nonce96::from_qb64(&qb64).unwrap();
        assert_eq!(nonce, parsed);
    }

    #[test]
    fn test_nonce_from_bytes() {
        let raw = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce = Nonce96::new(raw);
        assert_eq!(nonce.to_bytes(), raw);

        let qb64 = nonce.qb64();
        let parsed = Nonce96::from_qb64(&qb64).unwrap();
        assert_eq!(parsed.to_bytes(), raw);
    }

    #[test]
    fn test_nonce_invalid_length() {
        // Too short (only code, no data)
        assert!(Nonce96::from_qb64("1AANAAAA").is_err());
        // Too long
        assert!(Nonce96::from_qb64("1AANtoolong0000000000").is_err());
    }

    #[test]
    fn test_nonce256_roundtrip() {
        let nonce = Nonce256::generate();
        let qb64 = nonce.qb64();
        assert!(qb64.starts_with('N'));
        assert_eq!(qb64.len(), 44);

        let parsed = Nonce256::from_qb64(&qb64).unwrap();
        assert_eq!(nonce, parsed);
    }

    #[test]
    fn test_nonce256_from_bytes() {
        let raw = [42u8; 32];
        let nonce = Nonce256::new(raw);
        assert_eq!(nonce.to_bytes(), raw);

        let qb64 = nonce.qb64();
        let parsed = Nonce256::from_qb64(&qb64).unwrap();
        assert_eq!(parsed.to_bytes(), raw);
    }

    #[test]
    fn test_nonce256_invalid_length() {
        // Too short
        assert!(Nonce256::from_qb64("NAAAA").is_err());
        // Too long
        assert!(Nonce256::from_qb64("NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    }
}
