//! Base64url Encoding/Decoding
//!
//! CESR uses Base64url (RFC 4648) without padding for text representation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::CesrError;

/// Encode bytes to Base64url string (no padding)
pub fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode Base64url string to bytes (no padding expected)
pub fn b64_decode(s: &str) -> Result<Vec<u8>, CesrError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CesrError::InvalidBase64(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(b64_encode(&[]), "");
    }

    #[test]
    fn test_encode_single_byte() {
        // 'f' = 0x66 = 0110 0110
        // Split: 011001 100000 (padded)
        // = 25, 32 = "Zg"
        assert_eq!(b64_encode(b"f"), "Zg");
    }

    #[test]
    fn test_encode_two_bytes() {
        // "fo" = 0x66 0x6F = 0110 0110 0110 1111
        // Split: 011001 100110 111100 (padded)
        // = 25, 38, 60 = "Zm8"
        assert_eq!(b64_encode(b"fo"), "Zm8");
    }

    #[test]
    fn test_encode_three_bytes() {
        // "foo" = 0x66 0x6F 0x6F
        assert_eq!(b64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn test_roundtrip() {
        let original = b"Hello, CESR World!";
        let encoded = b64_encode(original);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_binary() {
        let original: Vec<u8> = (0..=255).collect();
        let encoded = b64_encode(&original);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_invalid() {
        assert!(b64_decode("!!!").is_err());
    }
}
