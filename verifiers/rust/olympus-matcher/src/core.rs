//! Pure-Rust core types, PyO3-free.
//!
//! All matching logic lives here so that it can be tested with a plain
//! `cargo test` without requiring a Python interpreter to be linked.

use crate::adl::adl_to_regex;
use crate::error::OlympusMatcherError;
use regex::Regex;

/// The result of a single pattern match attempt (pure-Rust layer).
#[derive(Debug, Clone)]
pub struct CoreMatchResult {
    pub matched: bool,
    pub pattern: String,
    pub span: Option<(usize, usize)>,
    pub captures: Vec<String>,
}

impl Default for CoreMatcher {
    fn default() -> Self {
        CoreMatcher::new()
    }
}

/// A compiled set of named patterns (pure-Rust layer).
pub struct CoreMatcher {
    pub(crate) patterns: Vec<(String, Regex)>,
}

impl CoreMatcher {
    /// Create a new, empty matcher.
    pub fn new() -> Self {
        CoreMatcher { patterns: Vec::new() }
    }

    /// Compile an ADL pattern and add it under `name`.
    pub fn add_pattern(&mut self, name: &str, adl_pattern: &str) -> Result<(), OlympusMatcherError> {
        let regex_str = adl_to_regex(adl_pattern)?;
        let re = Regex::new(&regex_str).map_err(|e| OlympusMatcherError::InvalidPattern {
            pattern: adl_pattern.to_owned(),
            reason: e.to_string(),
        })?;
        self.patterns.push((name.to_owned(), re));
        Ok(())
    }

    /// Add a raw regex string under `name`, bypassing the ADL compiler.
    pub fn add_raw_pattern(&mut self, name: &str, raw_regex: &str) -> Result<(), OlympusMatcherError> {
        let re = Regex::new(raw_regex).map_err(|e| OlympusMatcherError::InvalidPattern {
            pattern: raw_regex.to_owned(),
            reason: e.to_string(),
        })?;
        self.patterns.push((name.to_owned(), re));
        Ok(())
    }

    /// Run all patterns against `input` and return the first match.
    pub fn match_first(&self, input: &str) -> Option<CoreMatchResult> {
        for (name, re) in &self.patterns {
            if let Some(result) = try_match(name, re, input) {
                return Some(result);
            }
        }
        None
    }

    /// Run all patterns against `input` and return every match.
    pub fn match_all(&self, input: &str) -> Vec<CoreMatchResult> {
        self.patterns
            .iter()
            .filter_map(|(name, re)| try_match(name, re, input))
            .collect()
    }

    /// Return the list of loaded pattern names in insertion order.
    pub fn pattern_names(&self) -> Vec<String> {
        self.patterns.iter().map(|(n, _)| n.clone()).collect()
    }
}

/// Run a single compiled regex against `input` and produce a `CoreMatchResult`.
pub(crate) fn try_match(name: &str, re: &Regex, input: &str) -> Option<CoreMatchResult> {
    let caps = re.captures(input)?;
    let m = caps.get(0)?;
    let span = (m.start(), m.end());
    let captures: Vec<String> = caps
        .iter()
        .skip(1)
        .filter_map(|c| c.map(|m| m.as_str().to_owned()))
        .collect();
    Some(CoreMatchResult {
        matched: true,
        pattern: name.to_owned(),
        span: Some(span),
        captures,
    })
}
