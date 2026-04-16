//! PyO3 wrapper types: `Matcher` and `MatchResult`.
//!
//! All matching logic is delegated to [`crate::core`]; this module only
//! provides the Python-visible interface.

use pyo3::prelude::*;

use crate::core::{CoreMatchResult, CoreMatcher};
use crate::error::OlympusMatcherError;

// ── MatchResult ────────────────────────────────────────────────────────────

/// The result of a single pattern match attempt.
#[pyclass]
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Whether the pattern matched the input.
    #[pyo3(get)]
    pub matched: bool,

    /// The name of the pattern that produced this result.
    #[pyo3(get)]
    pub pattern: String,

    /// The byte span `(start, end)` of the match, if any.
    #[pyo3(get)]
    pub span: Option<(usize, usize)>,

    /// Captured groups (empty if the regex has no groups or there was no match).
    #[pyo3(get)]
    pub captures: Vec<String>,
}

impl From<CoreMatchResult> for MatchResult {
    fn from(r: CoreMatchResult) -> Self {
        MatchResult {
            matched: r.matched,
            pattern: r.pattern,
            span: r.span,
            captures: r.captures,
        }
    }
}

#[pymethods]
impl MatchResult {
    #[new]
    #[pyo3(signature = (matched, pattern, span=None, captures=vec![]))]
    pub fn new(
        matched: bool,
        pattern: String,
        span: Option<(usize, usize)>,
        captures: Vec<String>,
    ) -> Self {
        MatchResult {
            matched,
            pattern,
            span,
            captures,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "MatchResult(matched={}, pattern={:?}, span={:?})",
            if self.matched { "True" } else { "False" },
            self.pattern,
            self.span,
        )
    }
}

// ── Matcher ────────────────────────────────────────────────────────────────

/// A compiled set of named patterns.
///
/// All regex compilation occurs at pattern-load time (`add_pattern` /
/// `add_raw_pattern`); no re-compilation happens at match time.
#[pyclass]
pub struct Matcher {
    inner: CoreMatcher,
}

impl Default for Matcher {
    fn default() -> Self {
        Matcher::new()
    }
}

#[pymethods]
impl Matcher {
    /// Create a new, empty `Matcher`.
    #[new]
    pub fn new() -> Self {
        Matcher {
            inner: CoreMatcher::new(),
        }
    }

    /// Compile an ADL pattern and add it under `name`.
    ///
    /// Raises `ValueError` if the ADL expression or the resulting regex is
    /// invalid.  The error message includes the offending pattern string.
    pub fn add_pattern(&mut self, name: &str, adl_pattern: &str) -> PyResult<()> {
        self.inner
            .add_pattern(name, adl_pattern)
            .map_err(OlympusMatcherError::into)
    }

    /// Add a raw regex string under `name`, bypassing the ADL compiler.
    ///
    /// Raises `ValueError` if the regex fails to compile.
    pub fn add_raw_pattern(&mut self, name: &str, raw_regex: &str) -> PyResult<()> {
        self.inner
            .add_raw_pattern(name, raw_regex)
            .map_err(OlympusMatcherError::into)
    }

    /// Run all patterns against `input` and return the first match, or `None`.
    pub fn match_first(&self, input: &str) -> PyResult<Option<MatchResult>> {
        Ok(self.inner.match_first(input).map(MatchResult::from))
    }

    /// Run all patterns against `input` and return every match.
    pub fn match_all(&self, input: &str) -> PyResult<Vec<MatchResult>> {
        Ok(self
            .inner
            .match_all(input)
            .into_iter()
            .map(MatchResult::from)
            .collect())
    }

    /// Return the list of loaded pattern names, in insertion order.
    pub fn pattern_names(&self) -> Vec<String> {
        self.inner.pattern_names()
    }
}
