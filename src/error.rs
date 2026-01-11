//! CESR Error Types

use thiserror::Error;

/// Errors that can occur during CESR operations
#[derive(Error, Debug)]
pub enum CesrError {
    #[error("Invalid CESR code: {0}")]
    InvalidCode(String),

    #[error("Invalid Base64 encoding: {0}")]
    InvalidBase64(String),

    #[error("Invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Unknown primitive type: {0}")]
    UnknownType(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Parse error: {0}")]
    ParseError(String),
}

// Note: We use explicit conversions in code rather than From impls
// because p256::ecdsa::Error and ed25519_dalek::SignatureError both
// implement signature::Error which causes trait coherence conflicts.
