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

/// Signing public key algorithm codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyCode {
    /// secp256r1 (P-256) compressed public key (33 bytes)
    Secp256r1,
    /// ML-DSA-65 public key (1952 bytes)
    MlDsa65,
    /// ML-DSA-87 public key (2592 bytes)
    MlDsa87,
}

impl SigningKeyCode {
    /// CESR code string - transferable
    pub fn code(&self) -> &'static str {
        match self {
            SigningKeyCode::Secp256r1 => "1AAJ",
            SigningKeyCode::MlDsa65 => "b",
            SigningKeyCode::MlDsa87 => "1AAK",
        }
    }

    /// Raw key size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            SigningKeyCode::Secp256r1 => 33, // Compressed point
            SigningKeyCode::MlDsa65 => 1952,
            SigningKeyCode::MlDsa87 => 2592,
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        match self {
            SigningKeyCode::Secp256r1 => 48, // 4 + 44
            SigningKeyCode::MlDsa65 => 2604, // 1 + 2603 (1953 bytes → 2604 base64 chars)
            SigningKeyCode::MlDsa87 => 3460, // 4 + 3456 (2595 bytes → 3460 base64 chars)
        }
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "1AAJ" => Ok(SigningKeyCode::Secp256r1),
            "b" => Ok(SigningKeyCode::MlDsa65),
            "1AAK" => Ok(SigningKeyCode::MlDsa87),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        // Check multi-char codes first
        if qb64.starts_with("1AAJ") {
            Ok(SigningKeyCode::Secp256r1)
        } else if qb64.starts_with("1AAK") {
            Ok(SigningKeyCode::MlDsa87)
        } else if qb64.starts_with('b') {
            Ok(SigningKeyCode::MlDsa65)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(4).collect::<String>(),
            ))
        }
    }
}

/// KEM encapsulation key codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemKeyCode {
    /// ML-KEM-768 encapsulation key (1184 bytes)
    MlKem768,
    /// ML-KEM-1024 encapsulation key (1568 bytes)
    MlKem1024,
}

impl KemKeyCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            KemKeyCode::MlKem768 => "d",
            KemKeyCode::MlKem1024 => "g",
        }
    }

    /// Raw key size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            KemKeyCode::MlKem768 => 1184,
            KemKeyCode::MlKem1024 => 1568,
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        match self {
            KemKeyCode::MlKem768 => 1580, // 1 + 1579 (1185 bytes → 1580 base64 chars)
            KemKeyCode::MlKem1024 => 2092, // 1 + 2091 (1569 bytes → 2092 base64 chars)
        }
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "d" => Ok(KemKeyCode::MlKem768),
            "g" => Ok(KemKeyCode::MlKem1024),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with('d') {
            Ok(KemKeyCode::MlKem768)
        } else if qb64.starts_with('g') {
            Ok(KemKeyCode::MlKem1024)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(1).collect::<String>(),
            ))
        }
    }
}

/// KEM ciphertext codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemCiphertextCode {
    /// ML-KEM-768 ciphertext (1088 bytes)
    MlKem768,
    /// ML-KEM-1024 ciphertext (1568 bytes)
    MlKem1024,
}

impl KemCiphertextCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            KemCiphertextCode::MlKem768 => "e",
            KemCiphertextCode::MlKem1024 => "h",
        }
    }

    /// Raw ciphertext size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            KemCiphertextCode::MlKem768 => 1088,
            KemCiphertextCode::MlKem1024 => 1568,
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        match self {
            KemCiphertextCode::MlKem768 => 1452, // 1 + 1451 (1089 bytes → 1452 base64 chars)
            KemCiphertextCode::MlKem1024 => 2092, // 1 + 2091 (1569 bytes → 2092 base64 chars)
        }
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "e" => Ok(KemCiphertextCode::MlKem768),
            "h" => Ok(KemCiphertextCode::MlKem1024),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with('e') {
            Ok(KemCiphertextCode::MlKem768)
        } else if qb64.starts_with('h') {
            Ok(KemCiphertextCode::MlKem1024)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(1).collect::<String>(),
            ))
        }
    }
}

/// Private key seed codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedCode {
    /// secp256r1 (P-256) seed (32 bytes)
    Secp256r1,
    /// ML-DSA-65 seed (32 bytes)
    MlDsa65,
    /// ML-DSA-87 seed (32 bytes)
    MlDsa87,
}

impl SeedCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            SeedCode::Secp256r1 => "Q",
            SeedCode::MlDsa65 => "c",
            SeedCode::MlDsa87 => "f",
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
            "c" => Ok(SeedCode::MlDsa65),
            "f" => Ok(SeedCode::MlDsa87),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with('Q') {
            Ok(SeedCode::Secp256r1)
        } else if qb64.starts_with('c') {
            Ok(SeedCode::MlDsa65)
        } else if qb64.starts_with('f') {
            Ok(SeedCode::MlDsa87)
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
    /// ML-DSA-65 signature (3309 bytes)
    MlDsa65,
    /// ML-DSA-87 signature (4627 bytes)
    MlDsa87,
}

impl SignatureCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            SignatureCode::Secp256r1 => "0I",
            SignatureCode::MlDsa65 => "1AAQ",
            SignatureCode::MlDsa87 => "0J",
        }
    }

    /// Raw signature size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            SignatureCode::Secp256r1 => 64,
            SignatureCode::MlDsa65 => 3309,
            SignatureCode::MlDsa87 => 4627,
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        match self {
            SignatureCode::Secp256r1 => 88, // 2 + 86
            SignatureCode::MlDsa65 => 4416, // 4 + 4412 (3312 bytes → 4416 base64 chars)
            SignatureCode::MlDsa87 => 6172, // 2 + 6170 (4629 bytes → 6172 base64 chars)
        }
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "0I" => Ok(SignatureCode::Secp256r1),
            "1AAQ" => Ok(SignatureCode::MlDsa65),
            "0J" => Ok(SignatureCode::MlDsa87),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        // Check 4-char codes before 2-char codes
        if qb64.starts_with("1AAQ") {
            Ok(SignatureCode::MlDsa65)
        } else if qb64.starts_with("0I") {
            Ok(SignatureCode::Secp256r1)
        } else if qb64.starts_with("0J") {
            Ok(SignatureCode::MlDsa87)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(4).collect::<String>(),
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
    fn test_signing_key_codes() {
        assert_eq!(SigningKeyCode::Secp256r1.code(), "1AAJ");
        assert_eq!(SigningKeyCode::Secp256r1.raw_size(), 33);
        assert_eq!(SigningKeyCode::Secp256r1.qb64_size(), 48);

        assert_eq!(SigningKeyCode::MlDsa65.code(), "b");
        assert_eq!(SigningKeyCode::MlDsa65.raw_size(), 1952);
        assert_eq!(SigningKeyCode::MlDsa65.qb64_size(), 2604);

        assert_eq!(SigningKeyCode::MlDsa87.code(), "1AAK");
        assert_eq!(SigningKeyCode::MlDsa87.raw_size(), 2592);
        assert_eq!(SigningKeyCode::MlDsa87.qb64_size(), 3460);
    }

    #[test]
    fn test_kem_key_codes() {
        assert_eq!(KemKeyCode::MlKem768.code(), "d");
        assert_eq!(KemKeyCode::MlKem768.raw_size(), 1184);
        assert_eq!(KemKeyCode::MlKem768.qb64_size(), 1580);

        assert_eq!(KemKeyCode::MlKem1024.code(), "g");
        assert_eq!(KemKeyCode::MlKem1024.raw_size(), 1568);
        assert_eq!(KemKeyCode::MlKem1024.qb64_size(), 2092);
    }

    #[test]
    fn test_kem_ciphertext_codes() {
        assert_eq!(KemCiphertextCode::MlKem768.code(), "e");
        assert_eq!(KemCiphertextCode::MlKem768.raw_size(), 1088);
        assert_eq!(KemCiphertextCode::MlKem768.qb64_size(), 1452);

        assert_eq!(KemCiphertextCode::MlKem1024.code(), "h");
        assert_eq!(KemCiphertextCode::MlKem1024.raw_size(), 1568);
        assert_eq!(KemCiphertextCode::MlKem1024.qb64_size(), 2092);
    }

    #[test]
    fn test_signature_codes() {
        assert_eq!(SignatureCode::Secp256r1.code(), "0I");
        assert_eq!(SignatureCode::Secp256r1.raw_size(), 64);
        assert_eq!(SignatureCode::Secp256r1.qb64_size(), 88);

        assert_eq!(SignatureCode::MlDsa65.code(), "1AAQ");
        assert_eq!(SignatureCode::MlDsa65.raw_size(), 3309);
        assert_eq!(SignatureCode::MlDsa65.qb64_size(), 4416);

        assert_eq!(SignatureCode::MlDsa87.code(), "0J");
        assert_eq!(SignatureCode::MlDsa87.raw_size(), 4627);
        assert_eq!(SignatureCode::MlDsa87.qb64_size(), 6172);
    }

    #[test]
    fn test_seed_codes() {
        assert_eq!(SeedCode::Secp256r1.code(), "Q");
        assert_eq!(SeedCode::Secp256r1.raw_size(), 32);
        assert_eq!(SeedCode::Secp256r1.qb64_size(), 44);

        assert_eq!(SeedCode::MlDsa65.code(), "c");
        assert_eq!(SeedCode::MlDsa65.raw_size(), 32);
        assert_eq!(SeedCode::MlDsa65.qb64_size(), 44);

        assert_eq!(SeedCode::MlDsa87.code(), "f");
        assert_eq!(SeedCode::MlDsa87.raw_size(), 32);
        assert_eq!(SeedCode::MlDsa87.qb64_size(), 44);
    }

    #[test]
    fn test_signing_key_code_detect() {
        assert_eq!(
            SigningKeyCode::detect("1AAJsomething").unwrap(),
            SigningKeyCode::Secp256r1
        );
        assert_eq!(
            SigningKeyCode::detect("1AAKsomething").unwrap(),
            SigningKeyCode::MlDsa87
        );
        assert_eq!(
            SigningKeyCode::detect("bsomething").unwrap(),
            SigningKeyCode::MlDsa65
        );
        assert!(SigningKeyCode::detect("Xsomething").is_err());
    }

    #[test]
    fn test_kem_key_code_detect() {
        assert_eq!(
            KemKeyCode::detect("dsomething").unwrap(),
            KemKeyCode::MlKem768
        );
        assert_eq!(
            KemKeyCode::detect("gsomething").unwrap(),
            KemKeyCode::MlKem1024
        );
        assert!(KemKeyCode::detect("Xsomething").is_err());
    }

    #[test]
    fn test_kem_ciphertext_code_detect() {
        assert_eq!(
            KemCiphertextCode::detect("esomething").unwrap(),
            KemCiphertextCode::MlKem768
        );
        assert_eq!(
            KemCiphertextCode::detect("hsomething").unwrap(),
            KemCiphertextCode::MlKem1024
        );
        assert!(KemCiphertextCode::detect("Xsomething").is_err());
    }

    #[test]
    fn test_signature_code_detect() {
        assert_eq!(
            SignatureCode::detect("0Isomething").unwrap(),
            SignatureCode::Secp256r1
        );
        assert_eq!(
            SignatureCode::detect("1AAQsomething").unwrap(),
            SignatureCode::MlDsa65
        );
        assert_eq!(
            SignatureCode::detect("0Jsomething").unwrap(),
            SignatureCode::MlDsa87
        );
        assert!(SignatureCode::detect("XXsomething").is_err());
    }

    #[test]
    fn test_seed_code_detect() {
        assert_eq!(SeedCode::detect("Qsomething").unwrap(), SeedCode::Secp256r1);
        assert_eq!(SeedCode::detect("csomething").unwrap(), SeedCode::MlDsa65);
        assert_eq!(SeedCode::detect("fsomething").unwrap(), SeedCode::MlDsa87);
        assert!(SeedCode::detect("Xsomething").is_err());
    }
}
