use pyo3::prelude::*;
use pyo3::types::{PyDict, PyFrozenSet, PyList, PyTuple};

pub mod classfile;
pub mod jar;

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

/// Fast single-pass JAR scanner extracting ClassFacts and EntropyMetrics in native Rust.
#[pyfunction]
pub fn extract_jar_facts<'py>(py: Python<'py>, jar_path: &str) -> PyResult<Bound<'py, PyAny>> {
    let result = jar::scan_jar(jar_path)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let facts_mod = py.import("app.bytecode.facts")?;
    let class_facts_cls = facts_mod.getattr("ClassFacts")?;
    let jar_facts_cls = facts_mod.getattr("JarFacts")?;

    let entropy_mod = py.import("app.bytecode.entropy")?;
    let entropy_cls = entropy_mod.getattr("EntropyMetrics")?;

    let py_classes = PyList::empty(py);
    for c in result.classes {
        let method_refs = PyFrozenSet::new(py, &c.method_refs)?;
        let field_refs = PyFrozenSet::new(py, &c.field_refs)?;
        let class_refs = PyFrozenSet::new(py, &c.class_refs)?;
        let strings = PyFrozenSet::new(py, &c.strings)?;
        let float_constants = PyFrozenSet::new(py, &c.float_constants)?;
        let member_names = PyFrozenSet::new(py, &c.member_names)?;
        let member_homoglyphs = PyTuple::new(py, &c.member_homoglyphs)?;

        let mut ann_pairs = Vec::new();
        for (ann_type, elements) in c.annotations {
            let py_elements = PyDict::new(py);
            for (k, v) in elements {
                py_elements.set_item(k, v)?;
            }
            ann_pairs.push((ann_type, py_elements));
        }
        let annotations = PyTuple::new(py, ann_pairs)?;

        let py_m_by_m = PyDict::new(py);
        for (sig, refs) in c.method_refs_by_method {
            let f_set = PyFrozenSet::new(py, &refs)?;
            py_m_by_m.set_item(sig, f_set)?;
        }

        let class_facts = class_facts_cls.call1((
            c.class_name,
            c.simple_name,
            method_refs,
            field_refs,
            class_refs,
            strings,
            float_constants,
            annotations,
            member_names,
            c.char_append_count,
            member_homoglyphs,
            py_m_by_m,
        ))?;
        py_classes.append(class_facts)?;
    }

    let ent = result.entropy;
    let entropy_obj = entropy_cls.call1((
        ent.byte_entropy_avg,
        ent.byte_entropy_max,
        ent.high_entropy_classes,
        ent.high_entropy_strings,
        ent.short_name_ratio,
        ent.switch_density,
        ent.obfuscation_type,
    ))?;

    let jar_facts = jar_facts_cls.call1((
        py_classes,
        result.unparsed,
        result.hidden_class_entries,
        result.missing_entrypoints,
        entropy_obj,
    ))?;

    Ok(jar_facts)
}

#[pymodule]
fn mod_analyzer_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(string_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(is_encrypted_string, m)?)?;
    m.add_function(wrap_pyfunction!(count_high_entropy_strings, m)?)?;
    m.add_function(wrap_pyfunction!(extract_jar_facts, m)?)?;
    Ok(())
}
