//! Canonicalization for CD-HS-ST
//!
//! This module provides deterministic canonicalization for different content types.

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

/// Canonicalize content based on content type
pub fn canonicalize(content_type: &str, content: &[u8]) -> Result<Vec<u8>, String> {
    match content_type {
        "json" => canonicalize_json(content),
        "text" => canonicalize_text(content),
        _ => Err(format!("Unsupported content type: {}", content_type)),
    }
}

/// Canonicalize JSON content
fn canonicalize_json(content: &[u8]) -> Result<Vec<u8>, String> {
    // Parse JSON
    let value: Value = serde_json::from_slice(content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    // Serialize with sorted keys and no whitespace
    let canonical = serde_json::to_vec(&value)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;

    Ok(canonical)
}

/// Canonicalize text content
fn canonicalize_text(content: &[u8]) -> Result<Vec<u8>, String> {
    // Convert to UTF-8 string
    let text = std::str::from_utf8(content)
        .map_err(|e| format!("Invalid UTF-8: {}", e))?;

    // Apply NFC normalization
    let normalized: String = text.nfc().collect();

    // Normalize whitespace (collapse multiple spaces to single space)
    let normalized = normalized
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    Ok(normalized.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_json() {
        let json1 = br#"{"b": 2, "a": 1}"#;
        let json2 = br#"{"a":1,"b":2}"#;
        let json3 = br#"  {  "a"  :  1  ,  "b"  :  2  }  "#;

        let canonical1 = canonicalize("json", json1).unwrap();
        let canonical2 = canonicalize("json", json2).unwrap();
        let canonical3 = canonicalize("json", json3).unwrap();

        // All should produce the same canonical form
        assert_eq!(canonical1, canonical2);
        assert_eq!(canonical2, canonical3);

        // Should have sorted keys
        let canonical_str = std::str::from_utf8(&canonical1).unwrap();
        assert!(canonical_str.contains(r#""a""#));
        assert!(canonical_str.contains(r#""b""#));
    }

    #[test]
    fn test_canonicalize_text() {
        let text1 = b"hello   world";
        let text2 = b"hello world";
        let text3 = b"  hello  world  ";

        let canonical1 = canonicalize("text", text1).unwrap();
        let canonical2 = canonicalize("text", text2).unwrap();
        let canonical3 = canonicalize("text", text3).unwrap();

        // All should produce the same canonical form
        assert_eq!(canonical1, canonical2);
        assert_eq!(canonical2, canonical3);

        let canonical_str = std::str::from_utf8(&canonical1).unwrap();
        assert_eq!(canonical_str, "hello world");
    }

    #[test]
    fn test_unsupported_content_type() {
        let content = b"some content";
        let result = canonicalize("unsupported", content);
        assert!(result.is_err());
    }
}
