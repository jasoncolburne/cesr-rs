//! KEM Primitives
//!
//! CESR KEM primitives for key encapsulation:
//! - ML-KEM-768: 1184-byte encapsulation keys, 1-char code 'd' (1184 % 3 == 2)
//! - ML-KEM-768: 1088-byte ciphertexts, 1-char code 'e' (1088 % 3 == 2)

use fips203::traits::{
    Decaps as FipsDecaps, Encaps as FipsEncaps, KeyGen as FipsKemKeyGen, SerDes as FipsKemSerDes,
};
use fips203::{ml_kem_768, ml_kem_1024};

use crate::base64::{b64_decode, b64_encode};
use crate::codes::{KemCiphertextCode, KemKeyCode};
use crate::error::CesrError;
use crate::matter::Matter;

/// A KEM encapsulation key with CESR encoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemPublicKey {
    code: KemKeyCode,
    raw: Vec<u8>,
}

impl KemPublicKey {
    /// Create from raw bytes with specified algorithm
    pub fn from_raw(code: KemKeyCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }
        Ok(KemPublicKey { code, raw })
    }

    /// Get the KEM algorithm
    pub fn algorithm(&self) -> KemKeyCode {
        self.code
    }

    /// Encapsulate: produce a shared secret and ciphertext
    pub fn encapsulate(&self) -> Result<(KemCiphertext, [u8; 32]), CesrError> {
        match self.code {
            KemKeyCode::MlKem768 => {
                let ek_bytes: [u8; 1184] = self.raw.as_slice().try_into().map_err(|_| {
                    CesrError::CryptoError("invalid encapsulation key length".into())
                })?;
                let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let (ss, ct) = ek
                    .try_encaps()
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let ciphertext =
                    KemCiphertext::from_raw(KemCiphertextCode::MlKem768, ct.into_bytes().to_vec())?;
                Ok((ciphertext, ss.into_bytes()))
            }
            KemKeyCode::MlKem1024 => {
                let ek_bytes: [u8; 1568] = self.raw.as_slice().try_into().map_err(|_| {
                    CesrError::CryptoError("invalid encapsulation key length".into())
                })?;
                let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let (ss, ct) = ek
                    .try_encaps()
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let ciphertext = KemCiphertext::from_raw(
                    KemCiphertextCode::MlKem1024,
                    ct.into_bytes().to_vec(),
                )?;
                Ok((ciphertext, ss.into_bytes()))
            }
        }
    }
}

impl Matter for KemPublicKey {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        // All current KEM key codes are 1-char (1 pad byte)
        let mut padded = vec![0u8; 1];
        padded.extend_from_slice(&self.raw);
        let encoded = b64_encode(&padded);
        format!("{}{}", self.code.code(), &encoded[1..])
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = KemKeyCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let to_decode = format!("A{}", &qb64[1..]);
        let decoded = b64_decode(&to_decode)?;
        let raw = decoded[1..].to_vec();

        KemPublicKey::from_raw(code, raw)
    }
}

impl std::fmt::Display for KemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for KemPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
    }
}

impl<'de> serde::Deserialize<'de> for KemPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        KemPublicKey::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

/// A KEM decapsulation key (ephemeral, not CESR-encoded)
pub enum KemPrivateKey {
    /// ML-KEM-768 decapsulation key (2400 bytes serialized)
    MlKem768(Vec<u8>),
    /// ML-KEM-1024 decapsulation key (3168 bytes serialized)
    MlKem1024(Vec<u8>),
}

impl KemPrivateKey {
    /// Decapsulate: recover the shared secret from a ciphertext
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> Result<[u8; 32], CesrError> {
        match self {
            KemPrivateKey::MlKem768(bytes) => {
                let dk_bytes: [u8; 2400] = bytes.as_slice().try_into().map_err(|_| {
                    CesrError::CryptoError("invalid decapsulation key length".into())
                })?;
                let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let ct_bytes: [u8; 1088] = ciphertext
                    .raw()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid ciphertext length".into()))?;
                let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let ss = dk
                    .try_decaps(&ct)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Ok(ss.into_bytes())
            }
            KemPrivateKey::MlKem1024(bytes) => {
                let dk_bytes: [u8; 3168] = bytes.as_slice().try_into().map_err(|_| {
                    CesrError::CryptoError("invalid decapsulation key length".into())
                })?;
                let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let ct_bytes: [u8; 1568] = ciphertext
                    .raw()
                    .try_into()
                    .map_err(|_| CesrError::CryptoError("invalid ciphertext length".into()))?;
                let ct = ml_kem_1024::CipherText::try_from_bytes(ct_bytes)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                let ss = dk
                    .try_decaps(&ct)
                    .map_err(|e| CesrError::CryptoError(e.to_string()))?;
                Ok(ss.into_bytes())
            }
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> KemKeyCode {
        match self {
            KemPrivateKey::MlKem768(_) => KemKeyCode::MlKem768,
            KemPrivateKey::MlKem1024(_) => KemKeyCode::MlKem1024,
        }
    }
}

impl std::fmt::Debug for KemPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemPrivateKey::MlKem768(_) => write!(f, "KemPrivateKey::MlKem768([REDACTED])"),
            KemPrivateKey::MlKem1024(_) => write!(f, "KemPrivateKey::MlKem1024([REDACTED])"),
        }
    }
}

/// A KEM ciphertext with CESR encoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemCiphertext {
    code: KemCiphertextCode,
    raw: Vec<u8>,
}

impl KemCiphertext {
    /// Create from raw bytes with specified algorithm
    pub fn from_raw(code: KemCiphertextCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }
        Ok(KemCiphertext { code, raw })
    }

    /// Get the KEM algorithm
    pub fn algorithm(&self) -> KemCiphertextCode {
        self.code
    }
}

impl Matter for KemCiphertext {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        // All current KEM ciphertext codes are 1-char (1 pad byte)
        let mut padded = vec![0u8; 1];
        padded.extend_from_slice(&self.raw);
        let encoded = b64_encode(&padded);
        format!("{}{}", self.code.code(), &encoded[1..])
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = KemCiphertextCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let to_decode = format!("A{}", &qb64[1..]);
        let decoded = b64_decode(&to_decode)?;
        let raw = decoded[1..].to_vec();

        KemCiphertext::from_raw(code, raw)
    }
}

impl std::fmt::Display for KemCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for KemCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
    }
}

impl<'de> serde::Deserialize<'de> for KemCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        KemCiphertext::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

/// Generate a new ML-KEM-768 key pair
pub fn generate_ml_kem_768() -> Result<(KemPublicKey, KemPrivateKey), CesrError> {
    let (ek, dk) =
        ml_kem_768::KG::try_keygen().map_err(|e| CesrError::CryptoError(e.to_string()))?;
    let public = KemPublicKey::from_raw(KemKeyCode::MlKem768, ek.into_bytes().to_vec())?;
    let private = KemPrivateKey::MlKem768(dk.into_bytes().to_vec());
    Ok((public, private))
}

/// Generate a new ML-KEM-1024 key pair
pub fn generate_ml_kem_1024() -> Result<(KemPublicKey, KemPrivateKey), CesrError> {
    let (ek, dk) =
        ml_kem_1024::KG::try_keygen().map_err(|e| CesrError::CryptoError(e.to_string()))?;
    let public = KemPublicKey::from_raw(KemKeyCode::MlKem1024, ek.into_bytes().to_vec())?;
    let private = KemPrivateKey::MlKem1024(dk.into_bytes().to_vec());
    Ok((public, private))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_public_key_roundtrip() {
        let (public, _) = generate_ml_kem_768().unwrap();
        assert_eq!(public.algorithm(), KemKeyCode::MlKem768);
        assert_eq!(public.raw().len(), 1184);

        let qb64 = public.qb64();
        assert!(qb64.starts_with('d'));
        assert_eq!(qb64.len(), 1580);

        let parsed = KemPublicKey::from_qb64(&qb64).unwrap();
        assert_eq!(public, parsed);
    }

    #[test]
    fn test_kem_public_key_invalid_length() {
        let raw = vec![0x42u8; 100];
        assert!(KemPublicKey::from_raw(KemKeyCode::MlKem768, raw).is_err());
    }

    #[test]
    fn test_kem_ciphertext_roundtrip() {
        let (public, _) = generate_ml_kem_768().unwrap();
        let (ct, _ss) = public.encapsulate().unwrap();

        let qb64 = ct.qb64();
        assert!(qb64.starts_with('e'));
        assert_eq!(qb64.len(), 1452);

        let parsed = KemCiphertext::from_qb64(&qb64).unwrap();
        assert_eq!(ct, parsed);
    }

    #[test]
    fn test_kem_ciphertext_invalid_length() {
        let raw = vec![0x42u8; 100];
        assert!(KemCiphertext::from_raw(KemCiphertextCode::MlKem768, raw).is_err());
    }

    #[test]
    fn test_kem_encapsulate_decapsulate() {
        let (public, private) = generate_ml_kem_768().unwrap();
        let (ciphertext, shared_secret_enc) = public.encapsulate().unwrap();
        let shared_secret_dec = private.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn test_kem_generate() {
        let (public, private) = generate_ml_kem_768().unwrap();
        assert_eq!(public.algorithm(), KemKeyCode::MlKem768);
        assert_eq!(private.algorithm(), KemKeyCode::MlKem768);
    }

    #[test]
    fn test_kem_1024_public_key_roundtrip() {
        let (public, _) = generate_ml_kem_1024().unwrap();
        assert_eq!(public.algorithm(), KemKeyCode::MlKem1024);
        assert_eq!(public.raw().len(), 1568);

        let qb64 = public.qb64();
        assert!(qb64.starts_with('g'));
        assert_eq!(qb64.len(), 2092);

        let parsed = KemPublicKey::from_qb64(&qb64).unwrap();
        assert_eq!(public, parsed);
    }

    #[test]
    fn test_kem_1024_ciphertext_roundtrip() {
        let (public, _) = generate_ml_kem_1024().unwrap();
        let (ct, _ss) = public.encapsulate().unwrap();

        let qb64 = ct.qb64();
        assert!(qb64.starts_with('h'));
        assert_eq!(qb64.len(), 2092);

        let parsed = KemCiphertext::from_qb64(&qb64).unwrap();
        assert_eq!(ct, parsed);
    }

    #[test]
    fn test_kem_1024_encapsulate_decapsulate() {
        let (public, private) = generate_ml_kem_1024().unwrap();
        let (ciphertext, shared_secret_enc) = public.encapsulate().unwrap();
        let shared_secret_dec = private.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn test_kem_1024_generate() {
        let (public, private) = generate_ml_kem_1024().unwrap();
        assert_eq!(public.algorithm(), KemKeyCode::MlKem1024);
        assert_eq!(private.algorithm(), KemKeyCode::MlKem1024);
    }
}
