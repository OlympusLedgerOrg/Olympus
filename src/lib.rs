//! olympus_core — O(n) ADL pattern scanner for Python via PyO3.
//!
//! This module replaces the catastrophically-backtracking Pygments ADL lexer
//! patterns that are vulnerable to CVE-2026-4539 (GHSA-5239-wwwm-4pmq).
//!
//! Rust's `regex` crate uses a DFA/NFA hybrid engine that scans every input
//! character **at most once**, giving a strict O(n) time guarantee that Python's
//! `re` module — which uses a backtracking NFA — cannot provide.

use pyo3::prelude::*;
use regex::Regex;

/// O(n) ADL token scanner backed by Rust's non-backtracking regex engine.
///
/// Provides drop-in replacements for the two Pygments `AdlLexer` / `AtomsLexer`
/// patterns that cause catastrophic backtracking on adversarial input:
///
/// 1. **GUID/metadata** — `(\d|[a-fA-F])+(-(…)+){3,}` (line 296 of archetype.py)
/// 2. **Archetype ID**  — `([ \t]*)(([a-zA-Z]\w+…::)?[a-zA-Z]\w+…)` (AtomsLexer)
///
/// Both patterns are expressed with Rust syntax; because the engine is a DFA it
/// cannot backtrack and the match cost is proportional only to the input length.
#[pyclass]
pub struct AdlScanner {
    /// Matches the GUID/UUID-like hex pattern: `<hex>(-<hex>){3,}`
    guid_re: Regex,
    /// Matches archetype IDs such as `openEHR-EHR-OBSERVATION.blood_pressure.v1.0.0`
    /// Capture group 1 = leading whitespace, capture group 2 = the full archetype ID.
    archetype_id_re: Regex,
}

#[pymethods]
impl AdlScanner {
    #[new]
    pub fn new() -> PyResult<Self> {
        let guid_re = Regex::new(
            r"^[0-9a-fA-F]+(?:-[0-9a-fA-F]+){3,}",
        )
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let archetype_id_re = Regex::new(
            // Group 1: optional leading whitespace
            // Group 2: full archetype ID — optional "namespace::" prefix followed
            //          by "Class-Id-Id.concept.vN[.N[.N]][-qualifier[.N]]"
            r"^([ \t]*)((?:[a-zA-Z][a-zA-Z0-9_]+(?:\.[a-zA-Z][a-zA-Z0-9_]+)*::)?[a-zA-Z][a-zA-Z0-9_]+(?:-[a-zA-Z][a-zA-Z0-9_]+){2}\.[a-zA-Z0-9][a-zA-Z0-9_\-]*\.v[0-9]+(?:\.[0-9]+){0,2}(?:(?:-[a-z]+)(?:\.[0-9]+)?)?)",
        )
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(Self {
            guid_re,
            archetype_id_re,
        })
    }

    /// Match a GUID/hex pattern at byte offset `pos` in `text`.
    ///
    /// Returns `(start, end)` of the match, or `None` if no match.
    /// O(n) in the length of `text[pos..]`.
    ///
    /// Returns `None` (no panic) if `pos` is out of bounds or falls on a
    /// non-UTF-8 character boundary.
    pub fn match_guid(&self, text: &str, pos: usize) -> Option<(usize, usize)> {
        if pos > text.len() || !text.is_char_boundary(pos) {
            return None;
        }
        self.guid_re
            .find(&text[pos..])
            .map(|m| (pos, pos + m.end()))
    }

    /// Match an archetype ID at byte offset `pos` in `text`.
    ///
    /// Returns a list of capture-group spans `[(start, end), ...]` where index 0
    /// is the full match and indices 1, 2, … are capture groups.  Unmatched
    /// optional groups are represented as `None`.
    ///
    /// Returns `None` (no panic) if `pos` is out of bounds or falls on a
    /// non-UTF-8 character boundary.
    /// O(n) in the length of `text[pos..]`.
    pub fn match_archetype_id(
        &self,
        text: &str,
        pos: usize,
    ) -> Option<Vec<Option<(usize, usize)>>> {
        if pos > text.len() || !text.is_char_boundary(pos) {
            return None;
        }
        let slice = &text[pos..];
        self.archetype_id_re.captures(slice).map(|caps| {
            (0..caps.len())
                .map(|i| caps.get(i).map(|m| (pos + m.start(), pos + m.end())))
                .collect()
        })
    }

    /// Scan `text` for the first archetype ID anywhere in the string.
    ///
    /// Returns the matched substring or `None`.  Useful for standalone scanning
    /// outside of the Pygments lexer pipeline.
    pub fn scan_id(&self, text: &str) -> Option<String> {
        self.archetype_id_re
            .find(text)
            .map(|m| m.as_str().to_string())
    }
}

#[pymodule]
fn olympus_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AdlScanner>()?;
    Ok(())
}
