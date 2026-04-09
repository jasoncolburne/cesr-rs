//! CESR Nonce primitives

use crate::base64::{b64_decode, b64_encode};
use crate::codes::{Nonce96Code, Nonce256Code};
use crate::error::CesrError;
use crate::matter::Matter;

/// A CESR-encoded nonce.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce96 {
    code: Nonce96Code,
    raw: [u8; 12],
}

impl Nonce96 {
    /// Create from raw 12-byte nonce.
    pub fn new(raw: [u8; 12]) -> Self {
        Nonce96 {
            code: Nonce96Code::AesGcm256,
            raw,
        }
    }

    /// Generate a random nonce.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut raw = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut raw);
        Self::new(raw)
    }

    /// Get the raw bytes as a fixed-size array.
    pub fn to_bytes(&self) -> [u8; 12] {
        self.raw
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
        // 4-char code → 0 pad bytes
        let encoded = b64_encode(&self.raw);
        format!("{}{}", self.code.code(), encoded)
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

        Ok(Nonce96 { code, raw })
    }
}

impl std::fmt::Display for Nonce96 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for Nonce96 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce256 {
    code: Nonce256Code,
    raw: [u8; 32],
}

impl Nonce256 {
    /// Create from raw 32-byte nonce.
    pub fn new(raw: [u8; 32]) -> Self {
        Nonce256 {
            code: Nonce256Code::Random,
            raw,
        }
    }

    /// Generate a random nonce.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        Self::new(raw)
    }

    /// Get the raw bytes as a fixed-size array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.raw
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
        // 1-char code, 32 raw bytes → 1 pad byte
        let mut padded = vec![0u8];
        padded.extend_from_slice(&self.raw);
        let encoded = b64_encode(&padded);
        format!("{}{}", self.code.code(), &encoded[1..])
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

        Ok(Nonce256 { code, raw })
    }
}

impl std::fmt::Display for Nonce256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for Nonce256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
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
