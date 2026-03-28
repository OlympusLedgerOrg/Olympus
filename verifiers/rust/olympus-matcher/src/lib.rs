//! PyO3 module root for `olympus_matcher`.

use pyo3::prelude::*;

pub mod adl;
pub mod core;
pub mod error;
mod matcher;

pub use matcher::{MatchResult, Matcher};

#[pymodule]
fn olympus_matcher(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Matcher>()?;
    m.add_class::<MatchResult>()?;
    Ok(())
}
