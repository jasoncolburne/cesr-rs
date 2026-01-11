//! Matter Trait - Core CESR Primitive Abstraction
//!
//! All CESR primitives implement the Matter trait, providing
//! conversion between raw bytes and qb64 (qualified Base64url) representation.

use crate::error::CesrError;

/// Core trait for all CESR primitives
///
/// Matter provides the fundamental operations for CESR encoding:
/// - Converting to/from qualified Base64url (qb64)
/// - Accessing raw cryptographic material
/// - Identifying the primitive code
pub trait Matter: Sized {
    /// Get the CESR code for this primitive
    fn code(&self) -> &str;

    /// Get the raw cryptographic material (without code)
    fn raw(&self) -> &[u8];

    /// Get the qualified Base64url representation (code + encoded material)
    fn qb64(&self) -> String;

    /// Parse from qualified Base64url string
    fn from_qb64(qb64: &str) -> Result<Self, CesrError>;

    /// Get the size of the qb64 representation
    fn qb64_size(&self) -> usize {
        self.qb64().len()
    }
}
