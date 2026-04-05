//! CESR Code Definitions
//!
//! CESR uses self-describing codes to identify primitive types.
//! Codes are designed for 24-bit alignment (4 Base64 chars = 3 bytes).

use crate::error::CesrError;

/// Digest algorithm codes (1-character codes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DigestCode {
    /// Blake3-256 (32 bytes)
    Blake3,
}

impl DigestCode {
    /// CESR code character
    pub fn code(&self) -> &'static str {
        match self {
            DigestCode::Blake3 => "K",
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
            "K" => Ok(DigestCode::Blake3),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }
}

/// Signing public key algorithm codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerificationKeyCode {
    /// secp256r1 (P-256) compressed public key (33 bytes)
    Secp256r1,
    /// ML-DSA-65 public key (1952 bytes)
    MlDsa65,
    /// ML-DSA-87 public key (2592 bytes)
    MlDsa87,
}

impl VerificationKeyCode {
    /// CESR code string - transferable
    pub fn code(&self) -> &'static str {
        match self {
            VerificationKeyCode::Secp256r1 => "1AAC",
            VerificationKeyCode::MlDsa65 => "Q",
            VerificationKeyCode::MlDsa87 => "1AAU",
        }
    }

    /// Raw key size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            VerificationKeyCode::Secp256r1 => 33, // Compressed point
            VerificationKeyCode::MlDsa65 => 1952,
            VerificationKeyCode::MlDsa87 => 2592,
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        match self {
            VerificationKeyCode::Secp256r1 => 48, // 4 + 44
            VerificationKeyCode::MlDsa65 => 2604, // 1 + 2603 (1953 bytes → 2604 base64 chars)
            VerificationKeyCode::MlDsa87 => 3460, // 4 + 3456 (2595 bytes → 3460 base64 chars)
        }
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "1AAC" => Ok(VerificationKeyCode::Secp256r1),
            "Q" => Ok(VerificationKeyCode::MlDsa65),
            "1AAU" => Ok(VerificationKeyCode::MlDsa87),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        // Check multi-char codes first
        if qb64.starts_with("1AAC") {
            Ok(VerificationKeyCode::Secp256r1)
        } else if qb64.starts_with("1AAU") {
            Ok(VerificationKeyCode::MlDsa87)
        } else if qb64.starts_with('Q') {
            Ok(VerificationKeyCode::MlDsa65)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(4).collect::<String>(),
            ))
        }
    }
}

/// KEM encapsulation key codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EncapsulationKeyCode {
    /// ML-KEM-768 encapsulation key (1184 bytes)
    MlKem768,
    /// ML-KEM-1024 encapsulation key (1568 bytes)
    MlKem1024,
}

impl EncapsulationKeyCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            EncapsulationKeyCode::MlKem768 => "M",
            EncapsulationKeyCode::MlKem1024 => "H",
        }
    }

    /// Raw key size in bytes
    pub fn raw_size(&self) -> usize {
        match self {
            EncapsulationKeyCode::MlKem768 => 1184,
            EncapsulationKeyCode::MlKem1024 => 1568,
        }
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        self.code().len()
    }

    /// Full qb64 size
    pub fn qb64_size(&self) -> usize {
        match self {
            EncapsulationKeyCode::MlKem768 => 1580, // 1 + 1579 (1185 bytes → 1580 base64 chars)
            EncapsulationKeyCode::MlKem1024 => 2092, // 1 + 2091 (1569 bytes → 2092 base64 chars)
        }
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "M" => Ok(EncapsulationKeyCode::MlKem768),
            "H" => Ok(EncapsulationKeyCode::MlKem1024),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with('M') {
            Ok(EncapsulationKeyCode::MlKem768)
        } else if qb64.starts_with('H') {
            Ok(EncapsulationKeyCode::MlKem1024)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(1).collect::<String>(),
            ))
        }
    }
}

/// KEM ciphertext codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
            KemCiphertextCode::MlKem768 => "Y",
            KemCiphertextCode::MlKem1024 => "Z",
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
            "Y" => Ok(KemCiphertextCode::MlKem768),
            "Z" => Ok(KemCiphertextCode::MlKem1024),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with('Y') {
            Ok(KemCiphertextCode::MlKem768)
        } else if qb64.starts_with('Z') {
            Ok(KemCiphertextCode::MlKem1024)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(1).collect::<String>(),
            ))
        }
    }
}

/// Private key seed codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SigningKeySeedCode {
    /// secp256r1 (P-256) seed (32 bytes)
    Secp256r1,
    /// ML-DSA-65 seed (32 bytes)
    MlDsa65,
    /// ML-DSA-87 seed (32 bytes)
    MlDsa87,
}

impl SigningKeySeedCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            SigningKeySeedCode::Secp256r1 => "c",
            SigningKeySeedCode::MlDsa65 => "q",
            SigningKeySeedCode::MlDsa87 => "u",
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
            "c" => Ok(SigningKeySeedCode::Secp256r1),
            "q" => Ok(SigningKeySeedCode::MlDsa65),
            "u" => Ok(SigningKeySeedCode::MlDsa87),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with('c') {
            Ok(SigningKeySeedCode::Secp256r1)
        } else if qb64.starts_with('q') {
            Ok(SigningKeySeedCode::MlDsa65)
        } else if qb64.starts_with('u') {
            Ok(SigningKeySeedCode::MlDsa87)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(1).collect::<String>(),
            ))
        }
    }
}

/// KEM seed codes (64-byte seeds: d || z, each 32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KemSeedCode {
    /// ML-KEM-768 seed (64 bytes)
    MlKem768,
    /// ML-KEM-1024 seed (64 bytes)
    MlKem1024,
}

impl KemSeedCode {
    /// CESR code string
    pub fn code(&self) -> &'static str {
        match self {
            KemSeedCode::MlKem768 => "0m",
            KemSeedCode::MlKem1024 => "0h",
        }
    }

    /// Raw seed size in bytes
    pub fn raw_size(&self) -> usize {
        64
    }

    /// Code length in characters
    pub fn code_size(&self) -> usize {
        2
    }

    /// Full qb64 size (2 char code + 86 chars = 88)
    pub fn qb64_size(&self) -> usize {
        88
    }

    /// Parse from code string
    pub fn from_code(code: &str) -> Result<Self, CesrError> {
        match code {
            "0m" => Ok(KemSeedCode::MlKem768),
            "0h" => Ok(KemSeedCode::MlKem1024),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        if qb64.starts_with("0m") {
            Ok(KemSeedCode::MlKem768)
        } else if qb64.starts_with("0h") {
            Ok(KemSeedCode::MlKem1024)
        } else {
            Err(CesrError::InvalidCode(
                qb64.chars().take(2).collect::<String>(),
            ))
        }
    }

    /// Get the corresponding encapsulation key code
    pub fn encapsulation_key_code(&self) -> EncapsulationKeyCode {
        match self {
            KemSeedCode::MlKem768 => EncapsulationKeyCode::MlKem768,
            KemSeedCode::MlKem1024 => EncapsulationKeyCode::MlKem1024,
        }
    }
}

/// Signature algorithm codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
            SignatureCode::Secp256r1 => "0C",
            SignatureCode::MlDsa65 => "1AAQ",
            SignatureCode::MlDsa87 => "0U",
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
            "0C" => Ok(SignatureCode::Secp256r1),
            "1AAQ" => Ok(SignatureCode::MlDsa65),
            "0U" => Ok(SignatureCode::MlDsa87),
            _ => Err(CesrError::InvalidCode(code.to_string())),
        }
    }

    /// Try to detect code from qb64 string start
    pub fn detect(qb64: &str) -> Result<Self, CesrError> {
        // Check 4-char codes before 2-char codes
        if qb64.starts_with("1AAQ") {
            Ok(SignatureCode::MlDsa65)
        } else if qb64.starts_with("0C") {
            Ok(SignatureCode::Secp256r1)
        } else if qb64.starts_with("0U") {
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
        assert_eq!(DigestCode::Blake3.code(), "K");
        assert_eq!(DigestCode::Blake3.raw_size(), 32);
        assert_eq!(DigestCode::Blake3.qb64_size(), 44);
    }

    #[test]
    fn test_signing_key_codes() {
        assert_eq!(VerificationKeyCode::Secp256r1.code(), "1AAC");
        assert_eq!(VerificationKeyCode::Secp256r1.raw_size(), 33);
        assert_eq!(VerificationKeyCode::Secp256r1.qb64_size(), 48);

        assert_eq!(VerificationKeyCode::MlDsa65.code(), "Q");
        assert_eq!(VerificationKeyCode::MlDsa65.raw_size(), 1952);
        assert_eq!(VerificationKeyCode::MlDsa65.qb64_size(), 2604);

        assert_eq!(VerificationKeyCode::MlDsa87.code(), "1AAU");
        assert_eq!(VerificationKeyCode::MlDsa87.raw_size(), 2592);
        assert_eq!(VerificationKeyCode::MlDsa87.qb64_size(), 3460);
    }

    #[test]
    fn test_kem_key_codes() {
        assert_eq!(EncapsulationKeyCode::MlKem768.code(), "M");
        assert_eq!(EncapsulationKeyCode::MlKem768.raw_size(), 1184);
        assert_eq!(EncapsulationKeyCode::MlKem768.qb64_size(), 1580);

        assert_eq!(EncapsulationKeyCode::MlKem1024.code(), "H");
        assert_eq!(EncapsulationKeyCode::MlKem1024.raw_size(), 1568);
        assert_eq!(EncapsulationKeyCode::MlKem1024.qb64_size(), 2092);
    }

    #[test]
    fn test_kem_ciphertext_codes() {
        assert_eq!(KemCiphertextCode::MlKem768.code(), "Y");
        assert_eq!(KemCiphertextCode::MlKem768.raw_size(), 1088);
        assert_eq!(KemCiphertextCode::MlKem768.qb64_size(), 1452);

        assert_eq!(KemCiphertextCode::MlKem1024.code(), "Z");
        assert_eq!(KemCiphertextCode::MlKem1024.raw_size(), 1568);
        assert_eq!(KemCiphertextCode::MlKem1024.qb64_size(), 2092);
    }

    #[test]
    fn test_kem_seed_codes() {
        assert_eq!(KemSeedCode::MlKem768.code(), "0m");
        assert_eq!(KemSeedCode::MlKem768.raw_size(), 64);
        assert_eq!(KemSeedCode::MlKem768.qb64_size(), 88);

        assert_eq!(KemSeedCode::MlKem1024.code(), "0h");
        assert_eq!(KemSeedCode::MlKem1024.raw_size(), 64);
        assert_eq!(KemSeedCode::MlKem1024.qb64_size(), 88);
    }

    #[test]
    fn test_signature_codes() {
        assert_eq!(SignatureCode::Secp256r1.code(), "0C");
        assert_eq!(SignatureCode::Secp256r1.raw_size(), 64);
        assert_eq!(SignatureCode::Secp256r1.qb64_size(), 88);

        assert_eq!(SignatureCode::MlDsa65.code(), "1AAQ");
        assert_eq!(SignatureCode::MlDsa65.raw_size(), 3309);
        assert_eq!(SignatureCode::MlDsa65.qb64_size(), 4416);

        assert_eq!(SignatureCode::MlDsa87.code(), "0U");
        assert_eq!(SignatureCode::MlDsa87.raw_size(), 4627);
        assert_eq!(SignatureCode::MlDsa87.qb64_size(), 6172);
    }

    #[test]
    fn test_seed_codes() {
        assert_eq!(SigningKeySeedCode::Secp256r1.code(), "c");
        assert_eq!(SigningKeySeedCode::Secp256r1.raw_size(), 32);
        assert_eq!(SigningKeySeedCode::Secp256r1.qb64_size(), 44);

        assert_eq!(SigningKeySeedCode::MlDsa65.code(), "q");
        assert_eq!(SigningKeySeedCode::MlDsa65.raw_size(), 32);
        assert_eq!(SigningKeySeedCode::MlDsa65.qb64_size(), 44);

        assert_eq!(SigningKeySeedCode::MlDsa87.code(), "u");
        assert_eq!(SigningKeySeedCode::MlDsa87.raw_size(), 32);
        assert_eq!(SigningKeySeedCode::MlDsa87.qb64_size(), 44);
    }

    #[test]
    fn test_signing_key_code_detect() {
        assert_eq!(
            VerificationKeyCode::detect("1AACsomething").unwrap(),
            VerificationKeyCode::Secp256r1
        );
        assert_eq!(
            VerificationKeyCode::detect("1AAUsomething").unwrap(),
            VerificationKeyCode::MlDsa87
        );
        assert_eq!(
            VerificationKeyCode::detect("Qsomething").unwrap(),
            VerificationKeyCode::MlDsa65
        );
        assert!(VerificationKeyCode::detect("Xsomething").is_err());
    }

    #[test]
    fn test_kem_key_code_detect() {
        assert_eq!(
            EncapsulationKeyCode::detect("Msomething").unwrap(),
            EncapsulationKeyCode::MlKem768
        );
        assert_eq!(
            EncapsulationKeyCode::detect("Hsomething").unwrap(),
            EncapsulationKeyCode::MlKem1024
        );
        assert!(EncapsulationKeyCode::detect("Xsomething").is_err());
    }

    #[test]
    fn test_kem_ciphertext_code_detect() {
        assert_eq!(
            KemCiphertextCode::detect("Ysomething").unwrap(),
            KemCiphertextCode::MlKem768
        );
        assert_eq!(
            KemCiphertextCode::detect("Zsomething").unwrap(),
            KemCiphertextCode::MlKem1024
        );
        assert!(KemCiphertextCode::detect("Xsomething").is_err());
    }

    #[test]
    fn test_kem_seed_code_detect() {
        assert_eq!(
            KemSeedCode::detect("0msomething").unwrap(),
            KemSeedCode::MlKem768
        );
        assert_eq!(
            KemSeedCode::detect("0hsomething").unwrap(),
            KemSeedCode::MlKem1024
        );
        assert!(KemSeedCode::detect("0Xsomething").is_err());
    }

    #[test]
    fn test_signature_code_detect() {
        assert_eq!(
            SignatureCode::detect("0Csomething").unwrap(),
            SignatureCode::Secp256r1
        );
        assert_eq!(
            SignatureCode::detect("1AAQsomething").unwrap(),
            SignatureCode::MlDsa65
        );
        assert_eq!(
            SignatureCode::detect("0Usomething").unwrap(),
            SignatureCode::MlDsa87
        );
        assert!(SignatureCode::detect("XXsomething").is_err());
    }

    #[test]
    fn test_seed_code_detect() {
        assert_eq!(
            SigningKeySeedCode::detect("csomething").unwrap(),
            SigningKeySeedCode::Secp256r1
        );
        assert_eq!(
            SigningKeySeedCode::detect("qsomething").unwrap(),
            SigningKeySeedCode::MlDsa65
        );
        assert_eq!(
            SigningKeySeedCode::detect("usomething").unwrap(),
            SigningKeySeedCode::MlDsa87
        );
        assert!(SigningKeySeedCode::detect("Xsomething").is_err());
    }
}
