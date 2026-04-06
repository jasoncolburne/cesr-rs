//! KEM Primitives
//!
//! CESR KEM primitives for key encapsulation:
//! - ML-KEM-768/1024 encapsulation keys: 1-char codes 'M'/'H'
//! - ML-KEM-768/1024 ciphertexts: 1-char codes 'Y'/'Z'
//! - ML-KEM-768/1024 seeds: 2-char codes '0m'/'0h' (64-byte d||z)

use fips203::traits::{
    Decaps as FipsDecaps, Encaps as FipsEncaps, KeyGen as FipsKemKeyGen, SerDes as FipsKemSerDes,
};
use fips203::{ml_kem_768, ml_kem_1024};

use crate::base64::{b64_decode, b64_encode};
use crate::codes::{EncapsulationKeyCode, KemCiphertextCode, KemSeedCode};
use crate::error::CesrError;
use crate::matter::Matter;

/// A KEM encapsulation key with CESR encoding
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncapsulationKey {
    code: EncapsulationKeyCode,
    raw: Vec<u8>,
}

impl EncapsulationKey {
    /// Create from raw bytes with specified algorithm
    pub fn from_raw(code: EncapsulationKeyCode, raw: Vec<u8>) -> Result<Self, CesrError> {
        if raw.len() != code.raw_size() {
            return Err(CesrError::InvalidLength {
                expected: code.raw_size(),
                actual: raw.len(),
            });
        }
        Ok(EncapsulationKey { code, raw })
    }

    /// Get the KEM algorithm
    pub fn algorithm(&self) -> EncapsulationKeyCode {
        self.code
    }

    /// Encapsulate: produce a shared secret and ciphertext
    pub fn encapsulate(&self) -> Result<(KemCiphertext, [u8; 32]), CesrError> {
        match self.code {
            EncapsulationKeyCode::MlKem768 => {
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
            EncapsulationKeyCode::MlKem1024 => {
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

impl Matter for EncapsulationKey {
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
        let code = EncapsulationKeyCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let to_decode = format!("A{}", &qb64[1..]);
        let decoded = b64_decode(&to_decode)?;
        let raw = decoded[1..].to_vec();

        EncapsulationKey::from_raw(code, raw)
    }
}

impl std::fmt::Display for EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qb64())
    }
}

impl serde::Serialize for EncapsulationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.qb64())
    }
}

impl<'de> serde::Deserialize<'de> for EncapsulationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        EncapsulationKey::from_qb64(&s).map_err(serde::de::Error::custom)
    }
}

/// A KEM decapsulation key stored as a 64-byte seed (d || z).
///
/// The full decapsulation key is regenerated deterministically from the seed
/// when needed for decapsulation. This keeps storage compact (88 chars qb64)
/// versus storing the full key (2400/3168 bytes).
pub struct DecapsulationKey {
    code: KemSeedCode,
    seed: [u8; 64],
}

impl DecapsulationKey {
    /// Create from a raw 64-byte seed (d || z).
    pub fn from_seed(code: KemSeedCode, seed: [u8; 64]) -> Self {
        DecapsulationKey { code, seed }
    }

    /// Regenerate the full keypair from the seed.
    fn regenerate(&self) -> Result<(EncapsulationKey, Vec<u8>), CesrError> {
        let d: [u8; 32] = self.seed[..32]
            .try_into()
            .map_err(|_| CesrError::CryptoError("seed split failed".into()))?;
        let z: [u8; 32] = self.seed[32..]
            .try_into()
            .map_err(|_| CesrError::CryptoError("seed split failed".into()))?;

        match self.code {
            KemSeedCode::MlKem768 => {
                let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
                let public = EncapsulationKey::from_raw(
                    EncapsulationKeyCode::MlKem768,
                    ek.into_bytes().to_vec(),
                )?;
                Ok((public, dk.into_bytes().to_vec()))
            }
            KemSeedCode::MlKem1024 => {
                let (ek, dk) = ml_kem_1024::KG::keygen_from_seed(d, z);
                let public = EncapsulationKey::from_raw(
                    EncapsulationKeyCode::MlKem1024,
                    ek.into_bytes().to_vec(),
                )?;
                Ok((public, dk.into_bytes().to_vec()))
            }
        }
    }

    /// Derive the encapsulation (public) key from this seed.
    pub fn encapsulation_key(&self) -> Result<EncapsulationKey, CesrError> {
        let (ek, _) = self.regenerate()?;
        Ok(ek)
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> Result<[u8; 32], CesrError> {
        let (_, dk_bytes) = self.regenerate()?;

        match self.code {
            KemSeedCode::MlKem768 => {
                let dk_arr: [u8; 2400] = dk_bytes.as_slice().try_into().map_err(|_| {
                    CesrError::CryptoError("invalid decapsulation key length".into())
                })?;
                let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr)
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
            KemSeedCode::MlKem1024 => {
                let dk_arr: [u8; 3168] = dk_bytes.as_slice().try_into().map_err(|_| {
                    CesrError::CryptoError("invalid decapsulation key length".into())
                })?;
                let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_arr)
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
    pub fn algorithm(&self) -> EncapsulationKeyCode {
        self.code.encapsulation_key_code()
    }

    /// Get the seed code
    pub fn seed_code(&self) -> KemSeedCode {
        self.code
    }
}

impl Matter for DecapsulationKey {
    fn code(&self) -> &str {
        self.code.code()
    }

    fn raw(&self) -> &[u8] {
        &self.seed
    }

    fn qb64(&self) -> String {
        // 2-char code → 2 pad bytes
        let mut padded = vec![0u8; 2];
        padded.extend_from_slice(&self.seed);
        let encoded = b64_encode(&padded);
        format!("{}{}", self.code.code(), &encoded[2..])
    }

    fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        let code = KemSeedCode::detect(qb64)?;

        if qb64.len() != code.qb64_size() {
            return Err(CesrError::InvalidLength {
                expected: code.qb64_size(),
                actual: qb64.len(),
            });
        }

        let to_decode = format!("AA{}", &qb64[2..]);
        let decoded = b64_decode(&to_decode)?;
        let seed: [u8; 64] = decoded[2..]
            .try_into()
            .map_err(|_| CesrError::CryptoError("invalid seed length".into()))?;

        Ok(DecapsulationKey::from_seed(code, seed))
    }
}

impl std::fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecapsulationKey::{:?}([REDACTED])", self.code)
    }
}

/// A KEM ciphertext with CESR encoding
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// Generate a random 64-byte seed (d || z).
fn generate_kem_seed() -> [u8; 64] {
    use rand::RngCore;
    let mut seed = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

/// Generate a new ML-KEM-768 key pair from a random seed.
pub fn generate_ml_kem_768() -> Result<(EncapsulationKey, DecapsulationKey), CesrError> {
    let seed = generate_kem_seed();
    let private = DecapsulationKey::from_seed(KemSeedCode::MlKem768, seed);
    let public = private.encapsulation_key()?;
    Ok((public, private))
}

/// Generate a new ML-KEM-1024 key pair from a random seed.
pub fn generate_ml_kem_1024() -> Result<(EncapsulationKey, DecapsulationKey), CesrError> {
    let seed = generate_kem_seed();
    let private = DecapsulationKey::from_seed(KemSeedCode::MlKem1024, seed);
    let public = private.encapsulation_key()?;
    Ok((public, private))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_public_key_roundtrip() {
        let (public, _) = generate_ml_kem_768().unwrap();
        assert_eq!(public.algorithm(), EncapsulationKeyCode::MlKem768);
        assert_eq!(public.raw().len(), 1184);

        let qb64 = public.qb64();
        assert!(qb64.starts_with('M'));
        assert_eq!(qb64.len(), 1580);

        let parsed = EncapsulationKey::from_qb64(&qb64).unwrap();
        assert_eq!(public, parsed);
    }

    #[test]
    fn test_kem_public_key_invalid_length() {
        let raw = vec![0x42u8; 100];
        assert!(EncapsulationKey::from_raw(EncapsulationKeyCode::MlKem768, raw).is_err());
    }

    #[test]
    fn test_kem_ciphertext_roundtrip() {
        let (public, _) = generate_ml_kem_768().unwrap();
        let (ct, _ss) = public.encapsulate().unwrap();

        let qb64 = ct.qb64();
        assert!(qb64.starts_with('Y'));
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
        assert_eq!(public.algorithm(), EncapsulationKeyCode::MlKem768);
        assert_eq!(private.algorithm(), EncapsulationKeyCode::MlKem768);
    }

    #[test]
    fn test_kem_1024_public_key_roundtrip() {
        let (public, _) = generate_ml_kem_1024().unwrap();
        assert_eq!(public.algorithm(), EncapsulationKeyCode::MlKem1024);
        assert_eq!(public.raw().len(), 1568);

        let qb64 = public.qb64();
        assert!(qb64.starts_with('H'));
        assert_eq!(qb64.len(), 2092);

        let parsed = EncapsulationKey::from_qb64(&qb64).unwrap();
        assert_eq!(public, parsed);
    }

    #[test]
    fn test_kem_1024_ciphertext_roundtrip() {
        let (public, _) = generate_ml_kem_1024().unwrap();
        let (ct, _ss) = public.encapsulate().unwrap();

        let qb64 = ct.qb64();
        assert!(qb64.starts_with('Z'));
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
        assert_eq!(public.algorithm(), EncapsulationKeyCode::MlKem1024);
        assert_eq!(private.algorithm(), EncapsulationKeyCode::MlKem1024);
    }

    #[test]
    fn test_kem_768_seed_roundtrip() {
        let (_, private) = generate_ml_kem_768().unwrap();
        let qb64 = private.qb64();
        assert!(qb64.starts_with("0m"));
        assert_eq!(qb64.len(), 88);

        let parsed = DecapsulationKey::from_qb64(&qb64).unwrap();
        assert_eq!(parsed.seed_code(), KemSeedCode::MlKem768);
        assert_eq!(parsed.raw(), private.raw());
    }

    #[test]
    fn test_kem_1024_seed_roundtrip() {
        let (_, private) = generate_ml_kem_1024().unwrap();
        let qb64 = private.qb64();
        assert!(qb64.starts_with("0h"));
        assert_eq!(qb64.len(), 88);

        let parsed = DecapsulationKey::from_qb64(&qb64).unwrap();
        assert_eq!(parsed.seed_code(), KemSeedCode::MlKem1024);
        assert_eq!(parsed.raw(), private.raw());
    }

    #[test]
    fn test_kem_seed_deterministic() {
        let (pub1, priv1) = generate_ml_kem_768().unwrap();
        // Recreate from same seed
        let priv2 = DecapsulationKey::from_seed(KemSeedCode::MlKem768, priv1.seed);
        let pub2 = priv2.encapsulation_key().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_kem_seed_roundtrip_decapsulate() {
        let (public, private) = generate_ml_kem_768().unwrap();
        let qb64 = private.qb64();

        // Roundtrip seed through qb64
        let restored = DecapsulationKey::from_qb64(&qb64).unwrap();

        // Encapsulate with original public key, decapsulate with restored seed
        let (ciphertext, shared_secret_enc) = public.encapsulate().unwrap();
        let shared_secret_dec = restored.decapsulate(&ciphertext).unwrap();
        assert_eq!(shared_secret_enc, shared_secret_dec);
    }
}
