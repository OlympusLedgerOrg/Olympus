//! Canonical JSON (JCS / RFC 8785 with Olympus's Decimal numeric rules).
//!
//! Pure-Rust port of the PyO3 `src/canonical.rs` encoder, operating directly on
//! JSON **bytes** so it can be used from the desktop crate (no Python).
//! Byte-for-byte equivalent to `protocol/canonical_json.py`; the
//! `verifiers/test_vectors/canonicalizer_vectors.tsv` conformance suite gates
//! parity with the Python and JavaScript implementations.
//!
//! Rules:
//! - NFC normalization on all string keys and values
//! - object keys sorted by UTF-16 code-unit order (RFC 8785 §3.2.3)
//! - compact separators, no insignificant whitespace
//! - non-ASCII emitted as raw UTF-8
//! - every JSON number treated as an exact decimal (matches Python
//!   `json.loads(parse_float=Decimal)` + `Decimal.normalize()`); fixed notation
//!   when `-6 <= adjusted_exponent <= 20`, else scientific; `-0` → `0`
//! - rejects: invalid UTF-8, malformed JSON, trailing data, raw control bytes in
//!   strings, duplicate object keys (after NFC), and non-string object keys

use unicode_normalization::UnicodeNormalization;

/// Maximum nesting depth. Must equal the other canonicalizers — PyO3
/// `src/canonical.rs` and `verifiers/javascript` are both 64 — so a document one
/// implementation accepts can never be rejected by another; a mismatch here
/// would break cross-implementation digest parity. Also guards the recursive
/// encoder against stack overflow on hostile input.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    InvalidUtf8,
    Parse(String),
    TrailingData,
    DuplicateKey(String),
    NonStringKey,
    DepthExceeded,
    InvalidNumber(String),
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonError::InvalidUtf8 => write!(f, "input is not valid UTF-8"),
            CanonError::Parse(m) => write!(f, "JSON parse error: {m}"),
            CanonError::TrailingData => write!(f, "trailing data after JSON value"),
            CanonError::DuplicateKey(k) => write!(f, "duplicate key after NFC: {k:?}"),
            CanonError::NonStringKey => write!(f, "object keys must be strings"),
            CanonError::DepthExceeded => write!(f, "nesting depth exceeds {MAX_DEPTH}"),
            CanonError::InvalidNumber(n) => write!(f, "invalid number literal: {n}"),
        }
    }
}

impl std::error::Error for CanonError {}

/// Canonicalize JSON `input` bytes to canonical-JSON bytes (UTF-8).
pub fn canonicalize_bytes(input: &[u8]) -> Result<Vec<u8>, CanonError> {
    let s = std::str::from_utf8(input).map_err(|_| CanonError::InvalidUtf8)?;
    Ok(canonicalize_str(s)?.into_bytes())
}

/// Canonicalize a JSON `&str` to a canonical-JSON `String`.
pub fn canonicalize_str(input: &str) -> Result<String, CanonError> {
    let chars: Vec<char> = input.chars().collect();
    let mut p = Parser { chars: &chars, pos: 0 };
    p.skip_ws();
    let mut out = String::new();
    p.encode_value(0, &mut out)?;
    p.skip_ws();
    if p.pos != p.chars.len() {
        return Err(CanonError::TrailingData);
    }
    Ok(out)
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        // JSON insignificant whitespace: space, tab, LF, CR.
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: char) -> Result<(), CanonError> {
        if self.bump() == Some(c) {
            Ok(())
        } else {
            Err(CanonError::Parse(format!("expected '{c}'")))
        }
    }

    /// Parse one JSON value and append its canonical encoding to `out`.
    fn encode_value(&mut self, depth: usize, out: &mut String) -> Result<(), CanonError> {
        if depth > MAX_DEPTH {
            return Err(CanonError::DepthExceeded);
        }
        match self.peek() {
            Some('{') => self.encode_object(depth, out),
            Some('[') => self.encode_array(depth, out),
            Some('"') => {
                let s = self.parse_string()?;
                out.push_str(&encode_str(&nfc(&s)));
                Ok(())
            }
            Some('t') => {
                self.expect_lit("true")?;
                out.push_str("true");
                Ok(())
            }
            Some('f') => {
                self.expect_lit("false")?;
                out.push_str("false");
                Ok(())
            }
            Some('n') => {
                self.expect_lit("null")?;
                out.push_str("null");
                Ok(())
            }
            Some(c) if c == '-' || c.is_ascii_digit() => {
                let lit = self.parse_number_literal()?;
                out.push_str(&format_number(&lit)?);
                Ok(())
            }
            Some(c) => Err(CanonError::Parse(format!("unexpected character '{c}'"))),
            None => Err(CanonError::Parse("unexpected end of input".into())),
        }
    }

    fn expect_lit(&mut self, lit: &str) -> Result<(), CanonError> {
        for c in lit.chars() {
            if self.bump() != Some(c) {
                return Err(CanonError::Parse(format!("invalid literal, expected {lit}")));
            }
        }
        Ok(())
    }

    fn encode_array(&mut self, depth: usize, out: &mut String) -> Result<(), CanonError> {
        self.expect('[')?;
        out.push('[');
        self.skip_ws();
        if self.peek() == Some(']') {
            self.bump();
            out.push(']');
            return Ok(());
        }
        let mut first = true;
        loop {
            if !first {
                out.push(',');
            }
            first = false;
            self.skip_ws();
            self.encode_value(depth + 1, out)?;
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err(CanonError::Parse("expected ',' or ']' in array".into())),
            }
        }
        out.push(']');
        Ok(())
    }

    fn encode_object(&mut self, depth: usize, out: &mut String) -> Result<(), CanonError> {
        self.expect('{')?;
        self.skip_ws();
        let mut pairs: Vec<(String, String)> = Vec::new();
        if self.peek() == Some('}') {
            self.bump();
            out.push_str("{}");
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(CanonError::NonStringKey);
            }
            let key = nfc(&self.parse_string()?);
            if pairs.iter().any(|(k, _)| *k == key) {
                return Err(CanonError::DuplicateKey(key));
            }
            self.skip_ws();
            self.expect(':')?;
            self.skip_ws();
            let mut val = String::new();
            self.encode_value(depth + 1, &mut val)?;
            pairs.push((key, val));
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err(CanonError::Parse("expected ',' or '}' in object".into())),
            }
        }
        // Sort by UTF-16 code-unit order (RFC 8785 §3.2.3).
        pairs.sort_by(|a, b| {
            let a16: Vec<u16> = a.0.encode_utf16().collect();
            let b16: Vec<u16> = b.0.encode_utf16().collect();
            a16.cmp(&b16)
        });
        out.push('{');
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&encode_str(k));
            out.push(':');
            out.push_str(v);
        }
        out.push('}');
        Ok(())
    }

    /// Parse a JSON string (consuming the surrounding quotes). Rejects raw
    /// control characters (< U+0020); handles all standard escapes including
    /// `\uXXXX` surrogate pairs.
    fn parse_string(&mut self) -> Result<String, CanonError> {
        self.expect('"')?;
        let mut s = String::new();
        loop {
            match self.bump() {
                None => return Err(CanonError::Parse("unterminated string".into())),
                Some('"') => break,
                Some('\\') => {
                    let e = self
                        .bump()
                        .ok_or_else(|| CanonError::Parse("unterminated escape".into()))?;
                    match e {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'b' => s.push('\u{0008}'),
                        'f' => s.push('\u{000C}'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'u' => {
                            let cp = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // high surrogate: must be followed by \uDC00..DFFF
                                if self.bump() != Some('\\') || self.bump() != Some('u') {
                                    return Err(CanonError::Parse(
                                        "unpaired high surrogate".into(),
                                    ));
                                }
                                let lo = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err(CanonError::Parse(
                                        "invalid low surrogate".into(),
                                    ));
                                }
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                s.push(
                                    char::from_u32(c).ok_or_else(|| {
                                        CanonError::Parse("invalid surrogate pair".into())
                                    })?,
                                );
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err(CanonError::Parse("unpaired low surrogate".into()));
                            } else {
                                s.push(char::from_u32(cp).ok_or_else(|| {
                                    CanonError::Parse("invalid \\u escape".into())
                                })?);
                            }
                        }
                        other => {
                            return Err(CanonError::Parse(format!("invalid escape '\\{other}'")))
                        }
                    }
                }
                Some(c) if (c as u32) < 0x20 => {
                    // Raw control characters are not allowed in JSON strings.
                    return Err(CanonError::Parse(format!(
                        "raw control character U+{:04X} in string",
                        c as u32
                    )));
                }
                Some(c) => s.push(c),
            }
        }
        Ok(s)
    }

    fn parse_hex4(&mut self) -> Result<u32, CanonError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self
                .bump()
                .ok_or_else(|| CanonError::Parse("truncated \\u escape".into()))?;
            let d = c
                .to_digit(16)
                .ok_or_else(|| CanonError::Parse("invalid hex in \\u escape".into()))?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    /// Scan a JSON number literal per the RFC 8259 grammar (no leading zeros,
    /// optional fraction/exponent). Returns the raw token.
    fn parse_number_literal(&mut self) -> Result<String, CanonError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        // int: 0 | [1-9][0-9]*
        match self.peek() {
            Some('0') => {
                self.bump();
            }
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                    self.bump();
                }
            }
            _ => return Err(CanonError::InvalidNumber(self.slice_from(start))),
        }
        // frac
        if self.peek() == Some('.') {
            self.bump();
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return Err(CanonError::InvalidNumber(self.slice_from(start)));
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.bump();
            }
        }
        // exp
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.bump();
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.bump();
            }
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return Err(CanonError::InvalidNumber(self.slice_from(start)));
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.bump();
            }
        }
        Ok(self.slice_from(start))
    }

    fn slice_from(&self, start: usize) -> String {
        self.chars[start..self.pos].iter().collect()
    }
}

fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// Encode a string as a JSON string literal (JCS rules: raw UTF-8 for non-ASCII,
/// short escapes for the named control chars, `\uXXXX` for other C0 controls).
fn encode_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Format a JSON number literal as a normalized decimal, matching Python's
/// `Decimal(token).normalize()` followed by `_encode_number()`.
fn format_number(lit: &str) -> Result<String, CanonError> {
    let (sign, rest) = match lit.strip_prefix('-') {
        Some(r) => ("-", r),
        None => ("", lit),
    };
    // Split exponent.
    let (mant, exp_str) = match rest.find(['e', 'E']) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let mut exp: i64 = if exp_str.is_empty() {
        0
    } else {
        exp_str
            .parse()
            .map_err(|_| CanonError::InvalidNumber(lit.to_string()))?
    };
    // Split fraction.
    let (int_part, frac_part) = match mant.find('.') {
        Some(i) => (&mant[..i], &mant[i + 1..]),
        None => (mant, ""),
    };
    // Coefficient = integer digits ++ fraction digits; exponent shifts by frac len.
    let mut coeff: String = String::with_capacity(int_part.len() + frac_part.len());
    coeff.push_str(int_part);
    coeff.push_str(frac_part);
    exp -= frac_part.len() as i64;

    // Strip leading zeros (does not affect value or exponent).
    let trimmed = coeff.trim_start_matches('0');
    if trimmed.is_empty() {
        return Ok("0".to_string()); // zero (incl. -0) normalizes to "0"
    }
    let mut coeff = trimmed.to_string();
    // Decimal.normalize(): strip trailing zeros, raising the exponent.
    while coeff.len() > 1 && coeff.ends_with('0') {
        coeff.pop();
        exp += 1;
    }

    let adjusted = (coeff.len() as i64) - 1 + exp;
    let formatted = if (-6..=20).contains(&adjusted) {
        format_fixed(&coeff, exp)
    } else {
        format_scientific(&coeff, adjusted)
    };
    Ok(format!("{sign}{formatted}"))
}

fn format_fixed(digits: &str, exponent: i64) -> String {
    if exponent >= 0 {
        format!("{}{}", digits, "0".repeat(exponent as usize))
    } else {
        let idx = (digits.len() as i64) + exponent;
        if idx > 0 {
            let (int_part, frac_part) = digits.split_at(idx as usize);
            format!("{int_part}.{frac_part}")
        } else {
            format!("0.{}{}", "0".repeat((-idx) as usize), digits)
        }
    }
}

fn format_scientific(digits: &str, adjusted_exponent: i64) -> String {
    let mantissa = if digits.len() == 1 {
        digits.to_string()
    } else {
        format!("{}.{}", &digits[..1], &digits[1..])
    };
    let exp_sign = if adjusted_exponent >= 0 { "+" } else { "" };
    format!("{mantissa}e{exp_sign}{adjusted_exponent}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex in test vector")
    }

    /// Exact number of data rows in canonicalizer_vectors.tsv (total lines minus
    /// the header/comment/blank lines). Pinned so the suite can't silently shrink.
    const EXPECTED_VECTORS: usize = 780;

    #[test]
    fn conformance_vectors_byte_exact() {
        let tsv = include_str!("../../../verifiers/test_vectors/canonicalizer_vectors.tsv");
        let mut checked = 0usize;
        for line in tsv.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            assert_eq!(
                parts.len(),
                4,
                "malformed vector row (expected 4 tab-separated fields): {line:?}"
            );
            let (gid, input_hex, canon_hex, hash_hex) = (parts[0], parts[1], parts[2], parts[3]);
            let input = unhex(input_hex);
            let expected = unhex(canon_hex);
            let got = canonicalize_bytes(&input)
                .unwrap_or_else(|e| panic!("vector {gid} rejected unexpectedly: {e}"));
            assert_eq!(
                got,
                expected,
                "vector {gid}: canonical mismatch\n got: {}\n exp: {}",
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&expected)
            );
            // BLAKE3 of the canonical bytes must match the recorded hash.
            let h = blake3::hash(&got);
            assert_eq!(hex::encode(h.as_bytes()), hash_hex, "vector {gid}: hash mismatch");
            checked += 1;
        }
        assert_eq!(
            checked, EXPECTED_VECTORS,
            "expected {EXPECTED_VECTORS} canonicalizer vectors, ran {checked}"
        );
    }

    #[test]
    fn rejected_vectors_error() {
        let tsv = include_str!("../../../verifiers/test_vectors/canonicalizer_rejected.tsv");
        for line in tsv.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 2 {
                continue;
            }
            let (gid, input_hex) = (parts[0], parts[1]);
            let input = unhex(input_hex);
            assert!(
                canonicalize_bytes(&input).is_err(),
                "rejected vector {gid} was accepted"
            );
        }
    }

    #[test]
    fn nfc_distinct_pairs_differ() {
        // Both files hold (left, right) pairs that NFKC would collapse but NFC
        // (the normalization Olympus uses) keeps distinct — schema:
        // description, left_input_hex, right_input_hex, reason. Their canonical
        // forms must differ, proving the canonicalizer is NFC, not NFKC.
        for tsv in [
            include_str!("../../../verifiers/test_vectors/canonicalizer_space_equiv.tsv"),
            include_str!("../../../verifiers/test_vectors/canonicalizer_distinct.tsv"),
        ] {
            for line in tsv.lines() {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 3 {
                    continue;
                }
                let l = canonicalize_bytes(&unhex(parts[1]));
                let r = canonicalize_bytes(&unhex(parts[2]));
                if let (Ok(a), Ok(b)) = (&l, &r) {
                    assert_ne!(a, b, "pair {} must canonicalize to distinct forms", parts[0]);
                }
            }
        }
    }
}
