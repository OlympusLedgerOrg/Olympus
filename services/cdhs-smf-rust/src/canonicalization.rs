//! Canonicalization for CD-HS-ST
//!
//! This module provides deterministic, JCS/RFC 8785–compliant canonicalization
//! for different content types.  The output is byte-for-byte identical to the
//! reference implementations in `protocol/canonical_json.py` and
//! `protocol/canonical.py`.
//!
//! Supported content types:
//! - `"json"` — JCS (RFC 8785) canonical JSON
//! - `"text"` / `"plaintext"` — deterministic plain-text canonicalization

use std::collections::HashSet;

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Maximum nesting depth (prevent stack overflow on adversarial inputs)
// ---------------------------------------------------------------------------

/// Maximum JSON nesting depth accepted by the canonicalizer.
const MAX_JSON_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Canonicalize `content` according to `content_type`.
///
/// Returns the canonical bytes or an error string describing why the input
/// could not be canonicalized.
pub fn canonicalize(content_type: &str, content: &[u8]) -> Result<Vec<u8>, String> {
    match content_type {
        "json" => canonicalize_json(content),
        "text" | "plaintext" => canonicalize_plaintext(content),
        _ => Err(format!("Unsupported content type: {}", content_type)),
    }
}

// ---------------------------------------------------------------------------
// JSON canonicalization (JCS / RFC 8785)
// ---------------------------------------------------------------------------

/// Canonicalize JSON content following JCS (RFC 8785).
///
/// Rules (identical to `protocol/canonical_json.py`):
/// - NFC normalization on all string keys and values
/// - Duplicate key detection after NFC normalization
/// - Keys sorted lexicographically (by NFC-normalized key)
/// - No whitespace (compact separators)
/// - Non-ASCII characters emitted as raw UTF-8 (not `\uXXXX`)
/// - Control characters U+0000–U+001F use standard JSON escapes
/// - Numbers formatted per JCS: fixed when `-6 ≤ adjusted_exp ≤ 20`,
///   otherwise scientific with explicit `+`/`-` sign on the exponent
fn canonicalize_json(content: &[u8]) -> Result<Vec<u8>, String> {
    let value: Value =
        serde_json::from_slice(content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let mut out = Vec::with_capacity(content.len());
    encode_value_jcs(&value, &mut out, 0)?;
    Ok(out)
}

/// Recursively encode a `serde_json::Value` into JCS bytes.
fn encode_value_jcs(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!(
            "JSON nesting depth exceeds maximum of {}",
            MAX_JSON_DEPTH
        ));
    }

    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),

        Value::Number(n) => {
            let s = jcs_format_number(&n.to_string())?;
            out.extend_from_slice(s.as_bytes());
        }

        Value::String(s) => {
            let nfc: String = s.nfc().collect();
            encode_str_jcs(&nfc, out);
        }

        Value::Array(arr) => {
            out.push(b'[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_value_jcs(v, out, depth + 1)?;
            }
            out.push(b']');
        }

        Value::Object(map) => {
            // Collect with NFC-normalized keys and detect post-NFC duplicates.
            let mut pairs: Vec<(String, &Value)> = Vec::with_capacity(map.len());
            let mut seen: HashSet<String> = HashSet::with_capacity(map.len());
            for (k, v) in map.iter() {
                let nfc_k: String = k.nfc().collect();
                if !seen.insert(nfc_k.clone()) {
                    return Err(format!(
                        "Duplicate key after NFC normalization: {:?}",
                        nfc_k
                    ));
                }
                pairs.push((nfc_k, v));
            }
            // Sort by NFC-normalized key (lexicographic byte order).
            pairs.sort_by(|a, b| a.0.cmp(&b.0));

            out.push(b'{');
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_str_jcs(k, out);
                out.push(b':');
                encode_value_jcs(v, out, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Encode a Rust `&str` as a JSON string literal following JCS / RFC 8785.
///
/// Rules:
/// - `"` → `\"`
/// - `\` → `\\`
/// - U+0008 → `\b`, U+0009 → `\t`, U+000A → `\n`, U+000C → `\f`, U+000D → `\r`
/// - U+0000–U+001F (other) → `\uXXXX`
/// - All other code points (including non-ASCII) emitted as raw UTF-8.
fn encode_str_jcs(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\x0C' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                let escaped = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(escaped.as_bytes());
            }
            // Non-ASCII (U+0080 and above) — emit as raw UTF-8, JCS-compliant.
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ---------------------------------------------------------------------------
// JCS number formatting
// ---------------------------------------------------------------------------

/// Format a JSON number string following the JCS / RFC 8785 rules.
///
/// Maps to `protocol/canonical_json.py::_encode_number()`:
/// - Zero (including negative zero) → `"0"`
/// - Strip trailing zeros from significant digits
/// - Fixed notation when `-6 ≤ adjusted_exponent ≤ 20`
/// - Scientific notation otherwise, with explicit `+`/`-` on the exponent
///
/// The input `raw` is the string representation produced by `serde_json`'s
/// `Display` impl for `Number` (integers formatted without decimal point;
/// floats formatted by `ryu` in shortest-round-trip form).
fn jcs_format_number(raw: &str) -> Result<String, String> {
    let s = raw.trim();

    // Handle sign.
    let (negative, s) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else {
        (false, s)
    };

    // Split off the exponent part (if any).
    let e_pos = s.bytes().position(|b| b == b'e' || b == b'E');
    let (mantissa_str, json_exp): (&str, i64) = if let Some(i) = e_pos {
        let exp_str = &s[i + 1..];
        let exp: i64 = exp_str
            .parse()
            .map_err(|_| format!("Invalid exponent in number: {}", raw))?;
        (&s[..i], exp)
    } else {
        (s, 0)
    };

    // Split mantissa into integer and fraction parts.
    let (int_part, frac_part) = if let Some(dot_pos) = mantissa_str.find('.') {
        (&mantissa_str[..dot_pos], &mantissa_str[dot_pos + 1..])
    } else {
        (mantissa_str, "")
    };

    // Concatenate all digits; compute the base exponent (value of the
    // implicit decimal point relative to the first digit).
    let all_digits = format!("{}{}", int_part, frac_part);
    let base_exp: i64 = json_exp - frac_part.len() as i64;

    // Strip leading zeros (they do not contribute to the value).
    let trimmed_leading = all_digits.trim_start_matches('0');
    if trimmed_leading.is_empty() {
        // Value is zero (includes -0).
        return Ok("0".to_string());
    }

    // Strip trailing zeros from the significand; adjust the exponent accordingly.
    let trimmed = trimmed_leading.trim_end_matches('0');
    let trailing_zeros = (trimmed_leading.len() - trimmed.len()) as i64;
    let exponent = base_exp + trailing_zeros;

    // Number of remaining significant digits.
    let n = trimmed.len() as i64;

    // Adjusted exponent = exponent of the leading significant digit.
    let adjusted_exp = n - 1 + exponent;

    let formatted = if (-6..=20).contains(&adjusted_exp) {
        format_fixed_jcs(trimmed, exponent)
    } else {
        format_scientific_jcs(trimmed, adjusted_exp)
    };

    let sign = if negative { "-" } else { "" };
    Ok(format!("{}{}", sign, formatted))
}

/// Format `digits` in fixed (non-scientific) notation.
///
/// Mirrors `protocol/canonical_json.py::_format_fixed()`.
fn format_fixed_jcs(digits: &str, exponent: i64) -> String {
    if exponent >= 0 {
        format!("{}{}", digits, "0".repeat(exponent as usize))
    } else {
        let idx = digits.len() as i64 + exponent;
        if idx > 0 {
            let (int_part, frac_part) = digits.split_at(idx as usize);
            format!("{}.{}", int_part, frac_part)
        } else {
            let zeros = (-idx) as usize;
            format!("0.{}{}", "0".repeat(zeros), digits)
        }
    }
}

/// Format `digits` in scientific notation.
///
/// Mirrors `protocol/canonical_json.py::_format_scientific()`.
fn format_scientific_jcs(digits: &str, adjusted_exp: i64) -> String {
    let mantissa = if digits.len() == 1 {
        digits.to_string()
    } else {
        format!("{}.{}", &digits[..1], &digits[1..])
    };
    let exp_sign = if adjusted_exp >= 0 { "+" } else { "" };
    format!("{}e{}{}", mantissa, exp_sign, adjusted_exp)
}

// ---------------------------------------------------------------------------
// Plain-text canonicalization
// ---------------------------------------------------------------------------

/// Unicode space-like characters that NFC does not collapse to ASCII space.
///
/// Matches `protocol/canonical.py::_RESIDUAL_UNICODE_SPACES`.
fn replace_residual_spaces(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{00A0}' | '\u{202F}' => ' ',
            other => other,
        })
        .collect()
}

/// Replace a character whose NFKD decomposition is a single ASCII printable
/// character with that ASCII character.
///
/// Matches `protocol/canonical.py::_scrub_homoglyphs()`.
fn scrub_homoglyphs(text: &str) -> String {
    text.chars()
        .map(|ch| {
            let nfkd: String = ch.to_string().nfkd().collect();
            let chars: Vec<char> = nfkd.chars().collect();
            if chars.len() == 1 && (0x20u32..=0x7Eu32).contains(&(chars[0] as u32)) {
                chars[0]
            } else {
                ch
            }
        })
        .collect()
}

/// Canonicalize plain-text content for deterministic hashing.
///
/// Matches `protocol/canonical.py::canonicalize_plaintext()`:
///
/// 1. Strip BOM (U+FEFF).
/// 2. NFC normalization.
/// 3. Normalize line endings to `\n`.
/// 4. Per-line: replace NBSP-like chars, collapse whitespace.
/// 5. Homoglyph scrubbing (fullwidth → ASCII).
/// 6. Remove leading/trailing blank lines.
fn canonicalize_plaintext(content: &[u8]) -> Result<Vec<u8>, String> {
    let text =
        std::str::from_utf8(content).map_err(|e| format!("Invalid UTF-8: {}", e))?;

    // Step 1: Strip BOM.
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);

    // Step 2: NFC normalization.
    let text: String = text.nfc().collect();

    // Step 3: Normalize line endings (CRLF → LF, lone CR → LF).
    let text = text.replace("\r\n", "\n").replace('\r', "\n");

    // Steps 4–5: Per-line whitespace normalization and homoglyph scrubbing.
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|line| {
            // Replace residual Unicode space characters.
            let line = replace_residual_spaces(line);
            // Collapse whitespace and strip leading/trailing spaces within the line.
            let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
            // Homoglyph scrubbing.
            scrub_homoglyphs(&collapsed)
        })
        .collect();

    // Step 6: Remove leading blank lines.
    while !lines.is_empty() && lines[0].is_empty() {
        lines.remove(0);
    }
    // Remove trailing blank lines.
    while !lines.is_empty() && lines.last().map_or(true, |l| l.is_empty()) {
        lines.pop();
    }

    Ok(lines.join("\n").into_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // JSON canonicalization
    // -------------------------------------------------------------------------

    #[test]
    fn test_canonicalize_json_key_ordering() {
        let json1 = br#"{"b": 2, "a": 1}"#;
        let json2 = br#"{"a":1,"b":2}"#;
        let json3 = br#"  {  "a"  :  1  ,  "b"  :  2  }  "#;

        let c1 = canonicalize("json", json1).unwrap();
        let c2 = canonicalize("json", json2).unwrap();
        let c3 = canonicalize("json", json3).unwrap();

        assert_eq!(c1, c2);
        assert_eq!(c2, c3);

        let s = std::str::from_utf8(&c1).unwrap();
        assert_eq!(s, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_canonicalize_json_nfc_strings() {
        // "e" + combining acute (NFD) should normalize to precomposed "é" (NFC).
        let decomposed = "{\"e\u{0301}\": 1}";
        let precomposed = "{\"\u{00E9}\": 1}";

        let c_decomposed = canonicalize("json", decomposed.as_bytes()).unwrap();
        let c_precomposed = canonicalize("json", precomposed.as_bytes()).unwrap();

        assert_eq!(
            c_decomposed, c_precomposed,
            "NFC-equivalent keys must produce identical canonical JSON"
        );
    }

    #[test]
    fn test_canonicalize_json_string_value_nfc() {
        // String values must also be NFC normalized.
        let decomposed = b"{\"k\": \"e\xCC\x81\"}"; // e + combining acute
        let precomposed = b"{\"k\": \"\xC3\xA9\"}"; // é (U+00E9)

        let c1 = canonicalize("json", decomposed).unwrap();
        let c2 = canonicalize("json", precomposed).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_canonicalize_json_non_ascii_raw_utf8() {
        // Non-ASCII characters must be emitted as raw UTF-8, not \uXXXX.
        let input = b"{\"k\": \"\xC3\xA9\"}"; // {"k": "é"}
        let canonical = canonicalize("json", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        // Should not contain \u escape for é.
        assert!(!s.contains("\\u"), "non-ASCII must not be escaped as \\uXXXX");
        assert!(s.contains('\u{00E9}'), "é must appear as raw UTF-8");
    }

    #[test]
    fn test_canonicalize_json_control_chars_escaped() {
        let input = b"{\"k\": \"a\\nb\"}";
        let canonical = canonicalize("json", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert!(s.contains("\\n"));
    }

    #[test]
    fn test_canonicalize_json_numbers_integers() {
        let input = br#"{"a": 42, "b": -7, "c": 0}"#;
        let canonical = canonicalize("json", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        // Integers should appear without decimal points.
        assert_eq!(s, r#"{"a":42,"b":-7,"c":0}"#);
    }

    #[test]
    fn test_canonicalize_json_number_negative_zero() {
        // JSON -0 must normalize to 0.
        let input = br#"{"x": -0}"#;
        let canonical = canonicalize("json", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(s, r#"{"x":0}"#);
    }

    #[test]
    fn test_canonicalize_json_null_bool() {
        let input = br#"{"a": null, "b": true, "c": false}"#;
        let canonical = canonicalize("json", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(s, r#"{"a":null,"b":true,"c":false}"#);
    }

    #[test]
    fn test_canonicalize_json_nested() {
        let input = br#"{"z": [3, 1, 2], "a": {"y": false, "x": null}}"#;
        let canonical = canonicalize("json", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(s, r#"{"a":{"x":null,"y":false},"z":[3,1,2]}"#);
    }

    #[test]
    fn test_canonicalize_json_invalid() {
        let result = canonicalize("json", b"not json");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // JCS number formatting
    // -------------------------------------------------------------------------

    #[test]
    fn test_jcs_format_integer() {
        assert_eq!(jcs_format_number("42").unwrap(), "42");
        assert_eq!(jcs_format_number("-7").unwrap(), "-7");
        assert_eq!(jcs_format_number("100").unwrap(), "100");
    }

    #[test]
    fn test_jcs_format_zero() {
        assert_eq!(jcs_format_number("0").unwrap(), "0");
        assert_eq!(jcs_format_number("-0").unwrap(), "0");
        assert_eq!(jcs_format_number("0.0").unwrap(), "0");
    }

    #[test]
    fn test_jcs_format_decimal_fixed() {
        assert_eq!(jcs_format_number("3.14").unwrap(), "3.14");
        assert_eq!(jcs_format_number("0.5").unwrap(), "0.5");
        // 1e-6 has adjusted_exp = -6 → fixed notation
        assert_eq!(jcs_format_number("1e-6").unwrap(), "0.000001");
    }

    #[test]
    fn test_jcs_format_scientific() {
        // adjusted_exp > 20 → scientific
        assert_eq!(jcs_format_number("1.5e21").unwrap(), "1.5e+21");
        // adjusted_exp < -6 → scientific
        assert_eq!(jcs_format_number("1e-7").unwrap(), "1e-7");
        assert_eq!(jcs_format_number("1e21").unwrap(), "1e+21");
    }

    #[test]
    fn test_jcs_format_trailing_zeros_stripped() {
        // 1.50 → "1.5"
        assert_eq!(jcs_format_number("1.50").unwrap(), "1.5");
        // 1.500 → "1.5"
        assert_eq!(jcs_format_number("1.500").unwrap(), "1.5");
    }

    #[test]
    fn test_jcs_format_boundary_adjusted_exp() {
        // adjusted_exp = 20 → fixed (upper boundary, inclusive)
        // digits = "1", exponent = 20 → "1" + 20 zeros = "100000000000000000000" (10^20)
        assert_eq!(jcs_format_number("1e20").unwrap(), "100000000000000000000");
        // adjusted_exp = 21 → scientific
        assert_eq!(jcs_format_number("1e21").unwrap(), "1e+21");
        // adjusted_exp = -6 → fixed (lower boundary, inclusive)
        assert_eq!(jcs_format_number("1e-6").unwrap(), "0.000001");
        // adjusted_exp = -7 → scientific
        assert_eq!(jcs_format_number("1e-7").unwrap(), "1e-7");
    }

    // -------------------------------------------------------------------------
    // Plain-text canonicalization
    // -------------------------------------------------------------------------

    #[test]
    fn test_canonicalize_text_whitespace_collapse() {
        let t1 = b"hello   world";
        let t2 = b"hello world";
        let t3 = b"  hello  world  ";

        let c1 = canonicalize("text", t1).unwrap();
        let c2 = canonicalize("text", t2).unwrap();
        let c3 = canonicalize("text", t3).unwrap();

        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
        assert_eq!(std::str::from_utf8(&c1).unwrap(), "hello world");
    }

    #[test]
    fn test_canonicalize_plaintext_alias() {
        // "plaintext" must behave identically to "text".
        let input = b"hello   world";
        assert_eq!(
            canonicalize("text", input).unwrap(),
            canonicalize("plaintext", input).unwrap()
        );
    }

    #[test]
    fn test_canonicalize_text_crlf_normalization() {
        let unix = b"line1\nline2";
        let windows = b"line1\r\nline2";
        let old_mac = b"line1\rline2";

        let c_unix = canonicalize("text", unix).unwrap();
        let c_windows = canonicalize("text", windows).unwrap();
        let c_old_mac = canonicalize("text", old_mac).unwrap();

        assert_eq!(c_unix, c_windows);
        assert_eq!(c_unix, c_old_mac);
    }

    #[test]
    fn test_canonicalize_text_blank_line_trim() {
        let input = b"\nline1\nline2\n\n";
        let canonical = canonicalize("text", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(s, "line1\nline2");
    }

    #[test]
    fn test_canonicalize_text_bom_stripping() {
        // U+FEFF BOM prepended to content must be stripped.
        let with_bom = "\u{FEFF}hello world".as_bytes().to_vec();
        let without_bom = b"hello world";

        let c_bom = canonicalize("text", &with_bom).unwrap();
        let c_no_bom = canonicalize("text", without_bom).unwrap();

        assert_eq!(c_bom, c_no_bom);
    }

    #[test]
    fn test_canonicalize_text_unicode_spaces() {
        // NBSP (U+00A0) and NARROW NBSP (U+202F) must be replaced with ASCII space.
        let with_nbsp = "Hello\u{00A0}World\u{202F}Test".as_bytes().to_vec();
        let with_space = b"Hello World Test";

        let c1 = canonicalize("text", &with_nbsp).unwrap();
        let c2 = canonicalize("text", with_space).unwrap();

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_canonicalize_text_nfc_normalization() {
        // NFD "e" + combining acute must normalize to NFC precomposed "é".
        let nfd = "e\u{0301}".as_bytes().to_vec(); // NFD
        let nfc = "\u{00E9}".as_bytes().to_vec(); // NFC

        let c_nfd = canonicalize("text", &nfd).unwrap();
        let c_nfc = canonicalize("text", &nfc).unwrap();

        assert_eq!(c_nfd, c_nfc);
    }

    #[test]
    fn test_canonicalize_text_homoglyph_scrubbing() {
        // Fullwidth Latin 'Ａ' (U+FF21) should be scrubbed to ASCII 'A'.
        let fullwidth = "\u{FF21}".as_bytes().to_vec();
        let ascii = b"A";

        let c_fw = canonicalize("text", &fullwidth).unwrap();
        let c_ascii = canonicalize("text", ascii).unwrap();

        assert_eq!(c_fw, c_ascii);
    }

    #[test]
    fn test_canonicalize_text_preserves_internal_blank_lines() {
        // Blank lines in the middle of the text must be preserved.
        let input = b"line1\n\nline2";
        let canonical = canonicalize("text", input).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(s, "line1\n\nline2");
    }

    // -------------------------------------------------------------------------
    // Unsupported content type
    // -------------------------------------------------------------------------

    #[test]
    fn test_unsupported_content_type() {
        let result = canonicalize("unsupported", b"some content");
        assert!(result.is_err());
    }
}
