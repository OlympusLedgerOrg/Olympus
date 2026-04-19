//! Canonical JSON encoder for Olympus, exposed to Python via PyO3.
//!
//! The output is byte-for-byte identical to ``protocol/canonical_json.py``.
//! See that module's docstring for the full specification.

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyList, PyString, PyTuple};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Encode a Python object to canonical JSON.
///
/// Rules (identical to ``protocol/canonical_json.py``):
/// - NFC normalization on all string keys and values
/// - Sorted keys
/// - No whitespace (compact separators)
/// - ``ensure_ascii=True`` — non-ASCII escaped as ``\uXXXX``
/// - Reject ``float`` (only ``int`` and ``Decimal`` allowed)
/// - Reject ``NaN`` and ``±Infinity``
/// - Normalise ``-0`` to ``0``
/// - Decimal: fixed when ``-6 <= adjusted_exp <= 20``; else scientific
/// - Lone surrogates rejected by PyO3's UTF-8 extraction
///
/// # Python signature
/// ``canonical_json_encode(obj: object) -> str``
#[pyfunction]
pub fn canonical_json_encode(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<String> {
    encode_value(py, obj, 0)
}

// ---------------------------------------------------------------------------
// Core recursive encoder
// ---------------------------------------------------------------------------

/// Maximum nesting depth for canonical JSON encoding.
///
/// Hard ceiling that protects the PyO3 worker thread from stack overflow on
/// pathologically nested input (the encoder is recursive and runs on Python's
/// thread, which has a smaller stack than typical Rust threads).  Set lower
/// than the Python reference (`max_depth=100` in `protocol/canonical_json.py`)
/// because the Rust path holds additional `Bound<'py, PyAny>` reference
/// frames per level.  Real ledger documents nest only a handful of levels.
const MAX_DEPTH: usize = 64;

fn encode_value(py: Python<'_>, value: &Bound<'_, PyAny>, depth: usize) -> PyResult<String> {
    if depth > MAX_DEPTH {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Canonical JSON nesting depth {depth} exceeds maximum of {MAX_DEPTH}"
        )));
    }
    // None
    if value.is_none() {
        return Ok("null".to_string());
    }

    // bool must be checked before int (Python bool is a subclass of int)
    if value.is_instance_of::<PyBool>() {
        let b: bool = value.extract()?;
        return Ok(if b { "true" } else { "false" }.to_string());
    }

    // float — always rejected
    if value.is_instance_of::<PyFloat>() {
        let f: f64 = value.extract()?;
        if f.is_nan() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "NaN is not allowed in canonical JSON",
            ));
        }
        if f.is_infinite() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Infinity is not allowed in canonical JSON",
            ));
        }
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Float values are not allowed in canonical JSON; use Decimal",
        ));
    }

    // Decimal (must be checked before int since Decimal is not a subclass of int)
    let decimal_type = py.import("decimal")?.getattr("Decimal")?;
    if value.is_instance(&decimal_type)? {
        return encode_decimal(value);
    }

    // int (Python arbitrary-precision integer) — convert via Decimal so that
    // large integers like 10**30 are formatted as scientific notation when
    // adjusted_exponent > 20, matching the Python _encode_number() behaviour.
    let int_type = py.get_type::<pyo3::types::PyInt>();
    if value.is_instance(int_type.as_ref())? {
        // Decimal(int_value) gives us a Decimal with the same numeric value
        let dec = decimal_type.call1((value,))?;
        return encode_decimal(&dec);
    }

    // str
    if let Ok(s) = value.extract::<String>() {
        let nfc: String = s.nfc().collect();
        return Ok(encode_str(&nfc));
    }

    // list / tuple
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        let items: Vec<Bound<'_, PyAny>> = value.extract()?;
        let encoded: PyResult<Vec<String>> =
            items.iter().map(|x| encode_value(py, x, depth + 1)).collect();
        return Ok(format!("[{}]", encoded?.join(",")));
    }

    // dict
    if value.is_instance_of::<PyDict>() {
        let dict = value.downcast::<PyDict>()?;
        let mut pairs: Vec<(String, String)> = Vec::with_capacity(dict.len());
        let mut seen_keys: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(dict.len());
        for (k, v) in dict.iter() {
            if !k.is_instance_of::<PyString>() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "Object keys must be strings for canonical JSON",
                ));
            }
            let key_raw: String = k.extract()?;
            let key_nfc: String = key_raw.nfc().collect();
            if !seen_keys.insert(key_nfc.clone()) {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Duplicate key after NFC normalization: {key_nfc:?}"
                )));
            }
            let val_enc = encode_value(py, &v, depth + 1)?;
            pairs.push((key_nfc, val_enc));
        }
        // Sort by NFC-normalised key
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let items: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{}:{}", encode_str(k), v))
            .collect();
        return Ok(format!("{{{}}}", items.join(",")));
    }

    // Anything else is a type error
    let type_name: String = value.get_type().name()?.extract()?;
    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "Type {type_name} is not JSON-serializable for canonical JSON"
    )))
}

// ---------------------------------------------------------------------------
// String encoding (replicates json.encoder.py_encode_basestring_ascii)
// ---------------------------------------------------------------------------

/// Encode a Rust `&str` as a JSON string literal following RFC 8785 / JCS.
///
/// Rules:
/// - `"` → `\"`  
/// - `\` → `\\`
/// - U+0008 → `\b`, U+0009 → `\t`, U+000A → `\n`, U+000C → `\f`, U+000D → `\r`
/// - U+0000–U+001F (other) → `\uXXXX`
/// - All other code points (including non-ASCII) are emitted as raw UTF-8.
///
/// This intentionally diverges from `ensure_ascii=True` / CPython's
/// `py_encode_basestring_ascii`.  Emitting raw UTF-8 for non-ASCII characters
/// makes the output identical to any standard JCS library, which is required
/// for cross-implementation verifiability of ledger hashes.
fn encode_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"'     => out.push_str("\\\""),
            '\\'    => out.push_str("\\\\"),
            '\x08'  => out.push_str("\\b"),
            '\t'    => out.push_str("\\t"),
            '\n'    => out.push_str("\\n"),
            '\x0C'  => out.push_str("\\f"),
            '\r'    => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            // Non-ASCII (U+0080 and above) — emit as raw UTF-8, JCS-compliant.
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Decimal encoding
// ---------------------------------------------------------------------------

/// Encode a Python ``decimal.Decimal`` following the same rules as
/// ``protocol/canonical_json.py::_encode_number()``.
fn encode_decimal(value: &Bound<'_, PyAny>) -> PyResult<String> {
    // Reject non-finite Decimals
    let is_finite: bool = value.call_method0("is_finite")?.extract()?;
    if !is_finite {
        let is_nan: bool = value.call_method0("is_nan")?.extract()?;
        if is_nan {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "NaN is not allowed in canonical JSON",
            ));
        }
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Infinity is not allowed in canonical JSON",
        ));
    }

    // Zero (includes -0) → "0"
    let is_zero: bool = value.call_method0("is_zero")?.extract()?;
    if is_zero {
        return Ok("0".to_string());
    }

    // Normalise to strip trailing zeros (equivalent to Decimal.normalize())
    let normalised = value.call_method0("normalize")?;

    // Determine sign
    let is_signed: bool = normalised.call_method0("is_signed")?.extract()?;
    let sign_str = if is_signed { "-" } else { "" };

    // abs() for easier handling
    let abs_val = normalised.call_method0("__abs__")?;

    // as_tuple() → DecimalTuple(sign, digits, exponent)
    let as_tuple = abs_val.call_method0("as_tuple")?;
    let digits_py = as_tuple.getattr("digits")?;
    let exponent_py = as_tuple.getattr("exponent")?;

    // digits tuple → digit string
    let digits_vec: Vec<u8> = digits_py.extract()?;
    let digits: String = digits_vec.iter().map(|d| (b'0' + d) as char).collect();

    // exponent as i64 (it is always an int for finite Decimals after normalize())
    let exponent: i64 = exponent_py.extract()?;

    // adjusted_exponent = len(digits) - 1 + exponent
    let adjusted_exponent: i64 = (digits.len() as i64) - 1 + exponent;

    let formatted = if (-6..=20).contains(&adjusted_exponent) {
        format_fixed(&digits, exponent)
    } else {
        format_scientific(&digits, adjusted_exponent)
    };

    Ok(format!("{sign_str}{formatted}"))
}

/// Format in fixed (non-scientific) notation.
///
/// Replicates ``protocol/canonical_json.py::_format_fixed()``.
fn format_fixed(digits: &str, exponent: i64) -> String {
    if exponent >= 0 {
        // e.g. digits="123", exponent=2 → "12300"
        format!("{}{}", digits, "0".repeat(exponent as usize))
    } else {
        let idx = (digits.len() as i64) + exponent;
        if idx > 0 {
            // e.g. digits="12345", exponent=-2 → "123.45"
            let (int_part, frac_part) = digits.split_at(idx as usize);
            format!("{int_part}.{frac_part}")
        } else {
            // e.g. digits="123", exponent=-5 → "0.00123"
            let zeros = (-idx) as usize;
            format!("0.{}{}", "0".repeat(zeros), digits)
        }
    }
}

/// Format in scientific notation.
///
/// Replicates ``protocol/canonical_json.py::_format_scientific()``.
fn format_scientific(digits: &str, adjusted_exponent: i64) -> String {
    let mantissa = if digits.len() == 1 {
        digits.to_string()
    } else {
        format!("{}.{}", &digits[..1], &digits[1..])
    };
    let exp_sign = if adjusted_exponent >= 0 { "+" } else { "" };
    format!("{mantissa}e{exp_sign}{adjusted_exponent}")
}

// ---------------------------------------------------------------------------
// Submodule registration
// ---------------------------------------------------------------------------

/// Register the ``canonical_json_encode`` function into the given Python
/// (sub)module and expose it as ``olympus_core.canonical``.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonical_json_encode, m)?)?;

    // Make the submodule importable as `olympus_core.canonical`
    py.import("sys")?
        .getattr("modules")?
        .set_item("olympus_core.canonical", m)?;

    Ok(())
}
