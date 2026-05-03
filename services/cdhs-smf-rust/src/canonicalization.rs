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
// JSON canonicalization (JCS / RFC 8785) — single-pass recursive-descent
// ---------------------------------------------------------------------------

/// Canonicalize JSON content following JCS (RFC 8785).
///
/// Rules (identical to `protocol/canonical_json.py`):
/// - NFC normalization on all string keys and values
/// - Duplicate key detection **before** any library-level deduplication,
///   covering both byte-identical duplicates and NFC-equivalent duplicates
/// - Keys sorted by UTF-16 code-unit sequence (RFC 8785 §3.2.3).
///   See `protocol/canonical_json.py` which uses `k.encode("utf-16-be")`.
///   UTF-16 and Unicode scalar order agree for U+0000–U+D7FF and U+E000–U+FFFF
///   (BMP), but diverge for supplementary-plane characters (U+10000+): their
///   surrogate pairs (0xD800–0xDBFF / 0xDC00–0xDFFF) sort *before* the upper
///   BMP range U+E000–U+FFFF in UTF-16, while those code points sort *after*
///   U+FFFF in scalar order.  Using scalar order would produce different hashes
///   for objects with non-BMP keys — a silent cross-language consensus failure.
/// - No whitespace (compact separators)
/// - Non-ASCII characters emitted as raw UTF-8 (not `\uXXXX`)
/// - Control characters U+0000–U+001F use standard JSON escapes
/// - Numbers formatted per JCS: fixed when `-6 ≤ adjusted_exp ≤ 20`,
///   otherwise scientific with explicit `+`/`-` sign on the exponent
///
/// # Why a hand-written parser?
///
/// `serde_json::from_slice` silently deduplicates object keys (last-value-wins)
/// before we ever see them.  That means `{"a":1,"a":2}` would pass through our
/// previous post-parse `HashSet` duplicate check without triggering an error.
/// A canonicalizer that silently accepts ambiguous inputs is a security hazard
/// (two documents with different semantics could produce the same canonical
/// form).  `JcsParser` processes the raw bytes directly so that duplicate keys
/// are detected the moment the second key is parsed.
fn canonicalize_json(content: &[u8]) -> Result<Vec<u8>, String> {
    let mut parser = JcsParser::new(content);
    let mut out = Vec::with_capacity(content.len());
    parser.encode_value(&mut out, 0)?;
    // Reject trailing non-whitespace content (e.g. two top-level values).
    parser.skip_ws();
    if parser.peek().is_some() {
        return Err(format!(
            "unexpected trailing content at byte {}",
            parser.pos
        ));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// JcsParser — single-pass recursive-descent canonicalizer
// ---------------------------------------------------------------------------

/// Single-pass, streaming JSON canonicalizer.
///
/// Processes `input` byte-by-byte.  For each JSON value it encounters it
/// writes the JCS-canonical form directly to the caller-supplied `out`
/// buffer, without building an intermediate in-memory tree.  Object
/// key–value pairs are collected into a `Vec` so that they can be sorted
/// before being emitted; values are buffered per key.
struct JcsParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> JcsParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        JcsParser { input, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.advance();
        Some(b)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.advance();
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), String> {
        match self.consume() {
            Some(b) if b == expected => Ok(()),
            Some(b) => Err(format!(
                "at byte {}: expected {:?} but got {:?}",
                self.pos - 1,
                expected as char,
                b as char,
            )),
            None => Err(format!(
                "unexpected end of input; expected {:?}",
                expected as char,
            )),
        }
    }

    fn expect_literal(&mut self, lit: &[u8]) -> Result<(), String> {
        for &b in lit {
            self.expect_byte(b)?;
        }
        Ok(())
    }

    /// Parse a single hexadecimal digit and return its value (0–15).
    fn hex_digit(&mut self) -> Result<u16, String> {
        match self.consume() {
            Some(b) if b.is_ascii_digit() => Ok((b - b'0') as u16),
            Some(b) if (b'a'..=b'f').contains(&b) => Ok((b - b'a' + 10) as u16),
            Some(b) if (b'A'..=b'F').contains(&b) => Ok((b - b'A' + 10) as u16),
            Some(b) => Err(format!("invalid hex digit {:?}", b as char)),
            None => Err("unexpected end of input in \\u escape".to_string()),
        }
    }

    /// Parse four hex digits after `\u` and return the code-unit value.
    fn parse_hex4(&mut self) -> Result<u16, String> {
        let d0 = self.hex_digit()?;
        let d1 = self.hex_digit()?;
        let d2 = self.hex_digit()?;
        let d3 = self.hex_digit()?;
        Ok((d0 << 12) | (d1 << 8) | (d2 << 4) | d3)
    }

    /// Parse a JSON string literal (including the surrounding `"` quotes).
    ///
    /// Returns the unescaped, NFC-normalized Rust string, and also writes the
    /// JCS-encoded form of that string into `out`.
    fn parse_string(&mut self, out: &mut Vec<u8>) -> Result<String, String> {
        self.expect_byte(b'"')?;
        let mut unescaped = String::new();

        loop {
            match self.consume() {
                None => return Err("unterminated string literal".to_string()),
                Some(b'"') => break,
                Some(b'\\') => {
                    let ch = match self.consume() {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'/') => '/',
                        Some(b'b') => '\x08',
                        Some(b't') => '\t',
                        Some(b'n') => '\n',
                        Some(b'f') => '\x0C',
                        Some(b'r') => '\r',
                        Some(b'u') => {
                            let hi = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&hi) {
                                // High surrogate — must be followed by \uLLLL low surrogate.
                                if self.peek() == Some(b'\\') {
                                    self.advance();
                                    self.expect_byte(b'u')?;
                                    let lo = self.parse_hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(format!(
                                            "invalid surrogate pair \\u{:04X}\\u{:04X}",
                                            hi, lo
                                        ));
                                    }
                                    let cp = 0x10000u32
                                        + (u32::from(hi - 0xD800) << 10)
                                        + u32::from(lo - 0xDC00);
                                    char::from_u32(cp).ok_or_else(|| {
                                        format!("invalid code point U+{:X}", cp)
                                    })?
                                } else {
                                    return Err(format!(
                                        "lone high surrogate \\u{:04X}",
                                        hi
                                    ));
                                }
                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                return Err(format!("lone low surrogate \\u{:04X}", hi));
                            } else {
                                char::from_u32(u32::from(hi))
                                    .ok_or_else(|| format!("invalid code point U+{:X}", hi))?
                            }
                        }
                        Some(c) => return Err(format!("invalid escape \\{:?}", c as char)),
                        None => return Err("unterminated escape sequence".to_string()),
                    };
                    unescaped.push(ch);
                }
                Some(b) => {
                    if b < 0x20 {
                        return Err(format!(
                            "unescaped control character U+{:04X} in string",
                            b
                        ));
                    }
                    if b < 0x80 {
                        unescaped.push(b as char);
                    } else {
                        // Multi-byte UTF-8: collect the continuation bytes.
                        let width = utf8_seq_len(b);
                        if width == 0 {
                            return Err(format!("invalid UTF-8 lead byte 0x{:02X}", b));
                        }
                        let mut seq = [b, 0u8, 0u8, 0u8];
                        for seq_byte in seq.iter_mut().take(width).skip(1) {
                            match self.consume() {
                                Some(cont) if (cont & 0xC0) == 0x80 => *seq_byte = cont,
                                Some(cont) => {
                                    return Err(format!(
                                        "invalid UTF-8 continuation byte 0x{:02X}",
                                        cont
                                    ))
                                }
                                None => return Err("truncated UTF-8 sequence".to_string()),
                            }
                        }
                        let s = std::str::from_utf8(&seq[..width])
                            .map_err(|e| format!("invalid UTF-8 sequence: {}", e))?;
                        unescaped.push_str(s);
                    }
                }
            }
        }

        // NFC-normalize the unescaped content, then JCS-encode it.
        let nfc: String = unescaped.nfc().collect();
        encode_str_jcs(&nfc, out);
        Ok(nfc)
    }

    /// Consume a JSON number literal from the input; return the raw string.
    fn parse_number_raw(&mut self) -> Result<String, String> {
        let start = self.pos;

        // Optional leading minus.
        if self.peek() == Some(b'-') {
            self.advance();
        }

        // Integer part.
        match self.peek() {
            Some(b'0') => {
                self.advance();
                // JSON forbids leading zeros: `01` is not a valid number.
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(format!(
                        "leading zeros are not allowed in JSON numbers at byte {}",
                        self.pos
                    ));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.advance();
                }
            }
            _ => return Err(format!("expected digit at byte {}", self.pos)),
        }

        // Optional fractional part.
        if self.peek() == Some(b'.') {
            self.advance();
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("expected digit after '.'".to_string());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.advance();
            }
        }

        // Optional exponent.
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.advance();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.advance();
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("expected digit in exponent".to_string());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.advance();
            }
        }

        let raw = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| "number contains invalid bytes".to_string())?
            .to_string();
        Ok(raw)
    }

    /// Canonicalize the next JSON value and write it to `out`.
    fn encode_value(&mut self, out: &mut Vec<u8>, depth: usize) -> Result<(), String> {
        if depth > MAX_JSON_DEPTH {
            return Err(format!(
                "JSON nesting depth exceeds maximum of {}",
                MAX_JSON_DEPTH
            ));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'n') => {
                self.expect_literal(b"null")?;
                out.extend_from_slice(b"null");
            }
            Some(b't') => {
                self.expect_literal(b"true")?;
                out.extend_from_slice(b"true");
            }
            Some(b'f') => {
                self.expect_literal(b"false")?;
                out.extend_from_slice(b"false");
            }
            Some(b'"') => {
                self.parse_string(out)?;
            }
            Some(b'-') | Some(b'0'..=b'9') => {
                let raw = self.parse_number_raw()?;
                let formatted = jcs_format_number(&raw)?;
                out.extend_from_slice(formatted.as_bytes());
            }
            Some(b'[') => self.encode_array(out, depth)?,
            Some(b'{') => self.encode_object(out, depth)?,
            Some(b) => {
                return Err(format!(
                    "unexpected character {:?} at byte {}",
                    b as char,
                    self.pos
                ))
            }
            None => return Err("unexpected end of input".to_string()),
        }
        Ok(())
    }

    fn encode_array(&mut self, out: &mut Vec<u8>, depth: usize) -> Result<(), String> {
        self.expect_byte(b'[')?;
        out.push(b'[');
        self.skip_ws();

        if self.peek() == Some(b']') {
            self.advance();
            out.push(b']');
            return Ok(());
        }

        // First element.
        self.encode_value(out, depth + 1)?;
        self.skip_ws();

        // Subsequent elements.
        while self.peek() == Some(b',') {
            self.advance();
            out.push(b',');
            self.skip_ws();
            // Strict JSON: trailing commas are invalid.
            if self.peek() == Some(b']') {
                return Err("trailing comma in array".to_string());
            }
            self.encode_value(out, depth + 1)?;
            self.skip_ws();
        }

        self.expect_byte(b']')?;
        out.push(b']');
        Ok(())
    }

    fn encode_object(&mut self, out: &mut Vec<u8>, depth: usize) -> Result<(), String> {
        self.expect_byte(b'{')?;
        self.skip_ws();

        if self.peek() == Some(b'}') {
            self.advance();
            out.extend_from_slice(b"{}");
            return Ok(());
        }

        // Collect all key-value pairs into a Vec so we can sort them.
        // Using a Vec (not a Map) ensures that byte-identical duplicate keys
        // are visible to our duplicate check before any deduplication.
        let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        self.parse_kv_into(&mut pairs, &mut seen, depth)?;
        self.skip_ws();

        while self.peek() == Some(b',') {
            self.advance();
            self.skip_ws();
            // Strict JSON: trailing commas are invalid.
            if self.peek() == Some(b'}') {
                return Err("trailing comma in object".to_string());
            }
            self.parse_kv_into(&mut pairs, &mut seen, depth)?;
            self.skip_ws();
        }

        self.expect_byte(b'}')?;

        // RFC 8785 §3.2.3: sort keys by UTF-16 code-unit sequence.
        // `str::encode_utf16()` returns a lazy iterator; `Iterator::cmp` does
        // lexicographic comparison with short-circuit evaluation and zero
        // heap allocation — no Vec<u16> is ever materialised.
        pairs.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));

        out.push(b'{');
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            encode_str_jcs(k, out);
            out.push(b':');
            out.extend_from_slice(v);
        }
        out.push(b'}');
        Ok(())
    }

    /// Parse one `"key": value` pair into `pairs`.
    ///
    /// Rejects the pair if its NFC-normalized key was already seen (duplicate).
    fn parse_kv_into(
        &mut self,
        pairs: &mut Vec<(String, Vec<u8>)>,
        seen: &mut HashSet<String>,
        depth: usize,
    ) -> Result<(), String> {
        // Key — parse the raw string; the encoded form is discarded because we
        // re-encode keys after sorting in `encode_object`.
        let mut tmp = Vec::new();
        let nfc_key = self.parse_string(&mut tmp)?;

        // Duplicate check covers both byte-identical duplicates
        // (e.g. {"a":1,"a":2}) and NFC-equivalent duplicates
        // (e.g. {"e\u0301":1,"\u00e9":2}).
        if !seen.insert(nfc_key.clone()) {
            return Err(format!(
                "duplicate key after NFC normalization: {:?}",
                nfc_key
            ));
        }

        self.skip_ws();
        self.expect_byte(b':')?;
        self.skip_ws();

        // Value — canonicalize into a temporary buffer.
        let mut val_buf = Vec::new();
        self.encode_value(&mut val_buf, depth + 1)?;

        pairs.push((nfc_key, val_buf));
        Ok(())
    }
}

/// Return the expected byte-length of a UTF-8 sequence given its lead byte.
/// Returns 0 for invalid lead bytes (continuation bytes and overlong markers).
fn utf8_seq_len(first_byte: u8) -> usize {
    match first_byte {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 0,
    }
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
/// The input `raw` is the raw number string as it appears in the JSON source
/// (integers without decimal point; floats in standard decimal or scientific form).
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

    // Step 6: Remove leading blank lines — use drain for O(n) rather than
    // repeated remove(0) which would be O(n²).
    let first_non_empty = lines
        .iter()
        .position(|l| !l.is_empty())
        .unwrap_or(lines.len());
    lines.drain(..first_non_empty);

    // Remove trailing blank lines.
    while !lines.is_empty() && lines.last().map_or(false, |l| l.is_empty()) {
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

    #[test]
    fn test_canonicalize_json_rejects_byte_identical_duplicate_keys() {
        // {"a": 1, "a": 2} — serde_json would silently keep only one "a";
        // JcsParser detects the duplicate before any deduplication occurs.
        let input = br#"{"a": 1, "a": 2}"#;
        let result = canonicalize("json", input);
        assert!(
            result.is_err(),
            "byte-identical duplicate keys must be rejected"
        );
    }

    #[test]
    fn test_canonicalize_json_rejects_nfc_equivalent_duplicate_keys() {
        // "e\u0301" (NFD e-acute) and "\u00e9" (NFC precomposed e-acute) are
        // NFC-equivalent; the object must be rejected as having a duplicate key.
        let input = "{\"\u{0065}\u{0301}\": 1, \"\u{00E9}\": 2}";
        let result = canonicalize("json", input.as_bytes());
        assert!(
            result.is_err(),
            "NFC-equivalent duplicate keys must be rejected"
        );
    }

    // -------------------------------------------------------------------------
    // Non-BMP key ordering (RFC 8785 §3.2.3 / UTF-16 sort)
    //
    // These are the canonical cross-language conformance vectors also stored in
    // tests/conformance/vectors.json.  non-bmp-1 and non-bmp-2 are single-key
    // objects that confirm non-BMP keys round-trip through UTF-8 encoding
    // correctly; the sort divergence between Unicode scalar order and UTF-16
    // order is exercised by the multi-key vectors non-bmp-3 and non-bmp-4.
    // Expected bytes are derived from the Python reference (protocol/canonical_json.py).
    // -------------------------------------------------------------------------

    #[test]
    fn test_canonicalize_json_non_bmp_key_deseret_utf8() {
        // non-bmp-1: {𐐷:1}  canonical_hex = 7b22f09090b7223a317d
        let input = b"{\"\xf0\x90\x90\xb7\":1}";
        let canonical = canonicalize("json", input).unwrap();
        assert_eq!(canonical.as_slice(), b"{\"\xf0\x90\x90\xb7\":1}");
    }

    #[test]
    fn test_canonicalize_json_non_bmp_key_crab_emoji_utf8() {
        // non-bmp-2: {🦀:1}  canonical_hex = 7b22f09fa680223a317d
        let input = b"{\"\xf0\x9f\xa6\x80\":1}";
        let canonical = canonicalize("json", input).unwrap();
        assert_eq!(canonical.as_slice(), b"{\"\xf0\x9f\xa6\x80\":1}");
    }

    #[test]
    fn test_canonicalize_json_non_bmp_mixed_keys_utf16_order() {
        // non-bmp-3: input order a, 𐐷, b, 🦀
        // UTF-16 sort order: a[0x61] < b[0x62] < 𐐷[0xD801,...] < 🦀[0xD83E,...]
        // canonical_hex = 7b2261223a312c2262223a332c22f09090b7223a322c22f09fa680223a347d
        let input = b"{\"a\":1,\"\xf0\x90\x90\xb7\":2,\"b\":3,\"\xf0\x9f\xa6\x80\":4}";
        let canonical = canonicalize("json", input).unwrap();
        let expected = b"{\"a\":1,\"b\":3,\"\xf0\x90\x90\xb7\":2,\"\xf0\x9f\xa6\x80\":4}";
        assert_eq!(
            canonical.as_slice(),
            expected,
            "non-BMP keys must sort before U+E000–U+FFFF (UTF-16 surrogate < BMP upper)"
        );
    }

    #[test]
    fn test_canonicalize_json_non_bmp_bmp_boundary_utf16_order() {
        // non-bmp-4: keys U+E000, U+FFFD, U+10000 — input in scalar order
        // UTF-16 sort: U+10000[0xD800,0xDC00] < U+E000[0xE000] < U+FFFD[0xFFFD]
        // canonical_hex = 7b22f0908080223a2266697273742d73757070222c22ee8080223a22707561222c22efbfbd223a227265706c6163656d656e74227d
        let input = b"{\"\xee\x80\x80\":\"pua\",\"\xef\xbf\xbd\":\"replacement\",\"\xf0\x90\x80\x80\":\"first-supp\"}";
        let canonical = canonicalize("json", input).unwrap();
        // 𐀀 (U+10000, surrogates 0xD800/0xDC00) must come first
        let expected = b"{\"\xf0\x90\x80\x80\":\"first-supp\",\"\xee\x80\x80\":\"pua\",\"\xef\xbf\xbd\":\"replacement\"}";
        assert_eq!(
            canonical.as_slice(),
            expected,
            "U+10000 surrogate (0xD800) must sort before U+E000 in UTF-16 order"
        );
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
