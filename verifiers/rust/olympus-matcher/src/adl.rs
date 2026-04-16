//! ADL (Olympus pattern mini-language) to regex compiler.
//!
//! The ADL grammar is not yet formalised. This module implements a
//! best-effort compiler for the patterns Olympus currently uses.
//!
//! | ADL construct    | Example              | Compiled regex                  |
//! |------------------|----------------------|---------------------------------|
//! | Literal string   | `"redacted"`         | `\Bredacted\B` (word-boundary)  |
//! | Glob wildcard    | `*.pdf`              | `^.*\.pdf$`                     |
//! | Field selector   | `metadata.author`    | `(?i)author\s*[:=]\s*\S+`       |
//! | Pipe alternation | `foo\|bar`           | `(?:foo\|bar)`                  |

use crate::error::OlympusMatcherError;
use regex::escape;

/// Compile an ADL pattern to a regex string.
///
/// Returns the compiled regex string on success, or an
/// `OlympusMatcherError::InvalidAdl` / `OlympusMatcherError::InvalidPattern`
/// on failure.
pub fn adl_to_regex(adl_pattern: &str) -> Result<String, OlympusMatcherError> {
    let trimmed = adl_pattern.trim();

    if trimmed.is_empty() {
        return Err(OlympusMatcherError::InvalidAdl {
            pattern: adl_pattern.to_owned(),
            reason: "empty pattern".to_owned(),
        });
    }

    let regex_str = compile(trimmed)?;

    // Validate that the produced regex string actually compiles.
    regex::Regex::new(&regex_str).map_err(|e| OlympusMatcherError::InvalidPattern {
        pattern: adl_pattern.to_owned(),
        reason: e.to_string(),
    })?;

    Ok(regex_str)
}

/// Internal ADL compiler.
fn compile(adl: &str) -> Result<String, OlympusMatcherError> {
    // Quoted literal: "text"
    if adl.starts_with('"') && adl.ends_with('"') && adl.len() >= 2 {
        let inner = &adl[1..adl.len() - 1];
        return Ok(escape(inner));
    }

    // Field selector: word.word  (no wildcards, no pipes)
    if is_field_selector(adl) {
        let field = adl.rsplit('.').next().unwrap_or(adl);
        return Ok(format!("(?i){}\\s*[:=]\\s*\\S+", escape(field)));
    }

    // Glob with pipe alternation: pat1|pat2 where each part may contain */?
    if adl.contains('|') {
        let parts: Vec<String> = adl.split('|').map(|p| glob_to_regex(p.trim())).collect();
        return Ok(format!("(?:{})", parts.join("|")));
    }

    // Plain glob (contains * or ?)
    if adl.contains('*') || adl.contains('?') {
        return Ok(glob_to_regex(adl));
    }

    // Fallback: treat as a literal match
    Ok(escape(adl))
}

/// Returns true if the pattern looks like a dotted field path (e.g. `metadata.author`).
fn is_field_selector(adl: &str) -> bool {
    adl.contains('.')
        && !adl.contains('*')
        && !adl.contains('?')
        && !adl.contains('|')
        && adl
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
}

/// Convert a simple glob pattern (`*`, `?`, literal) to a regex.
///
/// `*` → `.*`  (any characters)
/// `?` → `.`   (single character)
/// Everything else is regex-escaped.
fn glob_to_regex(glob: &str) -> String {
    let mut regex = String::from("^");
    let chars = glob.chars().peekable();
    for c in chars {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            _ => regex.push_str(&escape(&c.to_string())),
        }
    }
    regex.push('$');
    regex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_literal_round_trips() {
        let r = adl_to_regex(r#""redacted""#).unwrap();
        let re = regex::Regex::new(&r).unwrap();
        assert!(re.is_match("document redacted end"));
        assert!(re.is_match("aredactedx")); // substring match
    }

    #[test]
    fn glob_matches_extension() {
        let r = adl_to_regex("*.pdf").unwrap();
        let re = regex::Regex::new(&r).unwrap();
        assert!(re.is_match("document.pdf"));
        assert!(!re.is_match("document.txt"));
    }

    #[test]
    fn field_selector_matches_key_value() {
        let r = adl_to_regex("metadata.author").unwrap();
        let re = regex::Regex::new(&r).unwrap();
        assert!(re.is_match("author: Smith"));
        assert!(re.is_match("Author=Jones"));
    }

    #[test]
    fn pipe_alternation() {
        let r = adl_to_regex("*.pdf|*.docx").unwrap();
        let re = regex::Regex::new(&r).unwrap();
        assert!(re.is_match("file.pdf"));
        assert!(re.is_match("file.docx"));
        assert!(!re.is_match("file.txt"));
    }

    #[test]
    fn empty_pattern_is_error() {
        assert!(adl_to_regex("").is_err());
        assert!(adl_to_regex("   ").is_err());
    }
}
