use pyo3::prelude::*;

/// Calculate Shannon entropy in bits per byte (0.0 to 8.0) rounded to 4 decimals.
#[pyfunction]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / total;
            entropy -= p * p.log2();
        }
    }
    (entropy * 10000.0).round() / 10000.0
}

/// Calculate Shannon entropy of a UTF-8 string.
#[pyfunction]
pub fn string_entropy(text: &str) -> f64 {
    shannon_entropy(text.as_bytes())
}

/// Determine if a string looks like an encrypted or packed pool literal.
#[pyfunction]
pub fn is_encrypted_string(s: &str) -> bool {
    let char_count = s.chars().count();
    if char_count < 20 {
        return false;
    }
    let non_ascii_count = s.chars().filter(|&ch| ch as u32 > 127).count();
    if non_ascii_count >= 8 {
        let ratio = (non_ascii_count as f64) / (char_count as f64);
        if ratio >= 0.4 && shannon_entropy(s.as_bytes()) >= 4.2 {
            return true;
        }
    }
    if char_count >= 64 && !s.contains(' ') && !s.contains('.') && !s.contains('/') {
        if shannon_entropy(s.as_bytes()) >= 5.0 {
            return true;
        }
    }
    false
}

/// Count encrypted strings from a list of strings.
#[pyfunction]
pub fn count_high_entropy_strings(strings: Vec<String>) -> usize {
    strings.iter().filter(|s| is_encrypted_string(s)).count()
}

#[pymodule]
fn mod_analyzer_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(string_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(is_encrypted_string, m)?)?;
    m.add_function(wrap_pyfunction!(count_high_entropy_strings, m)?)?;
    Ok(())
}
