#[cfg(feature = "python")]
use pyo3::prelude::*;

pub mod classfile;
pub mod cli;
pub mod hashing;
pub mod jar;
#[cfg(feature = "python")]
pub mod py_bridge;
pub mod rules;

#[cfg(feature = "python")]
pub use py_bridge::RuleEngine;
#[cfg(not(feature = "python"))]
pub use rules::engine::RuleEngine;

/// Calculate entropy in bits per byte (0.0 to 8.0) rounded to 4 decimals.
#[cfg_attr(feature = "python", pyfunction)]
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let val = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum::<f64>();
    (val * 10000.0).round() / 10000.0
}

/// Backwards compatibility alias for `entropy`.
#[cfg_attr(feature = "python", pyfunction)]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    entropy(data)
}

/// Calculate entropy of a UTF-8 string.
#[cfg_attr(feature = "python", pyfunction)]
pub fn string_entropy(text: &str) -> f64 {
    entropy(text.as_bytes())
}

/// Determine if a string looks like an encrypted or packed pool literal.
#[cfg_attr(feature = "python", pyfunction)]
pub fn is_encrypted_string(s: &str) -> bool {
    let char_count = s.chars().count();
    if char_count < 20 {
        return false;
    }

    let non_ascii_count = s.chars().filter(|&ch| !ch.is_ascii()).count();
    if non_ascii_count >= 8 {
        let ratio = (non_ascii_count as f64) / (char_count as f64);
        if ratio >= 0.4 && entropy(s.as_bytes()) >= 4.2 {
            return true;
        }
    }
    if char_count >= 64
        && !s.contains(' ')
        && !s.contains('.')
        && !s.contains('/')
        && entropy(s.as_bytes()) >= 5.0
    {
        return true;
    }
    false
}

/// Count encrypted strings from a list of strings.
#[cfg_attr(feature = "python", pyfunction)]
pub fn count_high_entropy_strings(strings: Vec<String>) -> usize {
    strings.iter().filter(|s| is_encrypted_string(s)).count()
}

/// Fast single-class parser extracting ClassFacts from raw bytecode.
#[cfg(feature = "python")]
#[pyfunction]
pub fn extract_class_facts<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let raw_data = classfile::parse_class(raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("Invalid or unparseable Java class bytes")
    })?;
    let facts_data = jar::build_class_facts_data(raw_data);
    let facts_mod = py.import("app.bytecode.facts")?;
    let class_facts_cls = facts_mod.getattr("ClassFacts")?;
    py_bridge::build_py_class_facts(py, &class_facts_cls, &facts_data)
}

/// Fast single-pass JAR scanner extracting ClassFacts and EntropyMetrics in native Rust without blocking GIL.
#[cfg(feature = "python")]
#[pyfunction]
pub fn extract_jar_facts<'py>(py: Python<'py>, jar_path: &str) -> PyResult<Bound<'py, PyAny>> {
    let result = py
        .detach(|| jar::scan_jar(jar_path))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    py_bridge::build_py_jar_facts(py, &result)
}

/// Compute SHA-512 hex digest of a file on disk without blocking GIL.
#[cfg(feature = "python")]
#[pyfunction]
pub fn sha512_file(py: Python<'_>, file_path: &str) -> PyResult<String> {
    py.detach(|| hashing::sha512_file(file_path))
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))
}

/// Compute SHA-512 hex digest of an in-memory byte slice.
#[cfg_attr(feature = "python", pyfunction)]
pub fn sha512_bytes(data: &[u8]) -> String {
    hashing::sha512_bytes(data)
}

#[cfg(feature = "python")]
#[pymodule]
fn mod_analyzer_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(entropy, m)?)?;
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(string_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(is_encrypted_string, m)?)?;
    m.add_function(wrap_pyfunction!(count_high_entropy_strings, m)?)?;
    m.add_function(wrap_pyfunction!(extract_class_facts, m)?)?;
    m.add_function(wrap_pyfunction!(extract_jar_facts, m)?)?;
    m.add_function(wrap_pyfunction!(sha512_file, m)?)?;
    m.add_function(wrap_pyfunction!(sha512_bytes, m)?)?;
    m.add_class::<RuleEngine>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_slice_is_zero() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_of_uniform_bytes() {
        let single_byte = [0x42; 100];
        assert_eq!(entropy(&single_byte), 0.0);
        assert_eq!(shannon_entropy(&single_byte), 0.0);

        let two_equal_bytes = [0x00, 0xFF, 0x00, 0xFF];
        assert_eq!(entropy(&two_equal_bytes), 1.0);
        assert_eq!(shannon_entropy(&two_equal_bytes), 1.0);
    }

    #[test]
    fn string_entropy_computes_utf8() {
        assert_eq!(string_entropy(""), 0.0);
        assert!(string_entropy("hello world") > 0.0);
    }

    #[test]
    fn is_encrypted_string_short_string_is_false() {
        assert!(!is_encrypted_string("short"));
    }

    #[test]
    fn is_encrypted_string_flags_high_entropy_non_ascii() {
        assert!(is_encrypted_string(
            "абвгдежзийклмнопрстуфхцчшщъыьэюя123456789"
        ));
    }
}
