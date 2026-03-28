use thiserror::Error;

/// Errors produced by the Olympus matcher.
#[derive(Debug, Error)]
pub enum OlympusMatcherError {
    /// A regex pattern failed to compile.
    #[error("invalid pattern {pattern:?}: {reason}")]
    InvalidPattern { pattern: String, reason: String },

    /// An ADL expression could not be parsed.
    #[error("invalid ADL expression {pattern:?}: {reason}")]
    InvalidAdl { pattern: String, reason: String },
}

impl From<OlympusMatcherError> for pyo3::PyErr {
    fn from(err: OlympusMatcherError) -> pyo3::PyErr {
        pyo3::exceptions::PyValueError::new_err(err.to_string())
    }
}
