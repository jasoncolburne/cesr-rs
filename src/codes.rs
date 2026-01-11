//! CESR Code Definitions
//!
//! CESR uses self-describing codes to identify primitive types.
//! Codes are designed for 24-bit alignment (4 Base64 chars = 3 bytes).

use crate::error::CesrError;

/// Digest algorithm codes (1-character codes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestCode {
    /// Blake3-256 (32 bytes)
    Blake3,
}

impl DigestCode {
    /// CESR code character
    pub fn code(&self) -> &'static str {
        match self {
            DigestCode::Blake3 => "E",
        }
    }

    /// Raw digest size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            DigestCode::Blake3 => 32,
        }
    }

    /// Full qb64 size (code + base64 data)
    pub fn qb64_size(&self) -> usize {
        // 1 char code + ceil(raw_size * 4 / 3) base64 chars
        // For 32 bytes: 1 + 43 = 44
        1 + (self.raw_size() * 4).div_ceil(3)
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "E" => Ok(DigestCode::Blake3),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }
}

/// Public key algorithm codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    /// secp256r1 (P-256) compressed public key (33 bytes)
    Secp256r1,
}

impl KeyCode {
    /// CESR code string - transferable
    pub fn code(&self) -> &'static str {
        match self {
            KeyCode::Secp256r1 => "1AAJ",
        }
    }

    /// Raw key size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            KeyCode::Secp256r1 => 33, // Compressed point
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        match self {
            KeyCode::Secp256r1 => 48, // 1AAB + 44 chars
        }
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "1AAJ" => Ok(KeyCode::Secp256r1),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with("1AAJ") {
            Ok(KeyCode::Secp256r1)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(4).collect::<String>(),
            ))
        }
    }
}

/// Private key seed codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedCode {
    /// secp256r1 (P-256) seed (32 bytes)
    Secp256r1,
}

impl SeedCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            SeedCode::Secp256r1 => "Q",
        }
    }

    /// Raw seed size in bytes
    pub fn raw_size(&self) -> usize {
        32
    }

    /// Full qb64 size (1 char code + 43 chars = 44)
    pub fn qb64_size(&self) -> usize {
        44
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "Q" => Ok(SeedCode::Secp256r1),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with('Q') {
            Ok(SeedCode::Secp256r1)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(1).collect::<String>(),
            ))
        }
    }
}

/// Signature algorithm codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCode {
    /// secp256r1 (P-256) ECDSA signature (64 bytes)
    Secp256r1,
}

impl SignatureCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            SignatureCode::Secp256r1 => "0I",
        }
    }

    /// Raw signature size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            SignatureCode::Secp256r1 => 64,
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        // 2 char code + 86 chars base64 for 64 bytes
        88
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "0I" => Ok(SignatureCode::Secp256r1),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with("0I") {
            Ok(SignatureCode::Secp256r1)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(2).collect::<String>(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_codes() {
        assert_eq!(DigestCode::Blake3.code(), "E");
        assert_eq!(DigestCode::Blake3.raw_size(), 32);
        assert_eq!(DigestCode::Blake3.qb64_size(), 44);
    }

    #[test]
    fn test_key_codes() {
        assert_eq!(KeyCode::Secp256r1.code(), "1AAJ");
    }

    #[test]
    fn test_signature_codes() {
        assert_eq!(SignatureCode::Secp256r1.code(), "0I");
    }
}
