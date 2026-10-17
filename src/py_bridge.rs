use pyo3::prelude::*;
use pyo3::types::{PyDict, PyFrozenSet, PyList, PyTuple};

use crate::jar::{self, ClassFactsData, JarFactsResult};
use crate::rules::{self, RawMatch};

pub fn build_py_class_facts<'py>(
    py: Python<'py>,
    class_facts_cls: &Bound<'py, PyAny>,
    c: &ClassFactsData,
) -> PyResult<Bound<'py, PyAny>> {
    let method_refs = PyFrozenSet::new(py, &c.method_refs)?;
    let field_refs = PyFrozenSet::new(py, &c.field_refs)?;
    let class_refs = PyFrozenSet::new(py, &c.class_refs)?;
    let strings = PyFrozenSet::new(py, &c.strings)?;
    let float_constants = PyFrozenSet::new(py, &c.float_constants)?;
    let member_names = PyFrozenSet::new(py, &c.member_names)?;
    let member_homoglyphs = PyTuple::new(py, &c.member_homoglyphs)?;

    let mut ann_pairs = Vec::new();
    for (ann_type, elements) in &c.annotations {
        let py_elements = PyDict::new(py);
        for (k, v) in elements {
            py_elements.set_item(k, v)?;
        }
        ann_pairs.push((ann_type, py_elements));
    }
    let annotations = PyTuple::new(py, ann_pairs)?;

    let py_m_by_m = PyDict::new(py);
    for (sig, refs) in &c.method_refs_by_method {
        let f_set = PyFrozenSet::new(py, refs)?;
        py_m_by_m.set_item(sig, f_set)?;
    }

    class_facts_cls.call1((
        &c.class_name,
        &c.simple_name,
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
    ))
}

pub fn build_py_entropy<'py>(
    py: Python<'py>,
    ent: &crate::jar::EntropyMetricsData,
) -> PyResult<Bound<'py, PyAny>> {
    let entropy_mod = py.import("app.bytecode.entropy")?;
    let entropy_cls = entropy_mod.getattr("EntropyMetrics")?;
    entropy_cls.call1((
        ent.byte_entropy_avg,
        ent.byte_entropy_max,
        ent.high_entropy_classes,
        ent.high_entropy_strings,
        ent.short_name_ratio,
        ent.switch_density,
        &ent.obfuscation_type,
    ))
}

pub fn build_py_jar_facts<'py>(
    py: Python<'py>,
    result: &JarFactsResult,
) -> PyResult<Bound<'py, PyAny>> {
    let facts_mod = py.import("app.bytecode.facts")?;
    let class_facts_cls = facts_mod.getattr("ClassFacts")?;
    let jar_facts_cls = facts_mod.getattr("JarFacts")?;

    let py_classes = PyList::empty(py);
    for c in &result.classes {
        let class_facts = build_py_class_facts(py, &class_facts_cls, c)?;
        py_classes.append(class_facts)?;
    }

    let entropy_obj = build_py_entropy(py, &result.entropy)?;

    jar_facts_cls.call1((
        py_classes,
        &result.unparsed,
        result.hidden_class_entries,
        &result.missing_entrypoints,
        entropy_obj,
    ))
}

pub fn build_py_matches<'py>(
    py: Python<'py>,
    raw_matches: &[RawMatch],
) -> PyResult<Bound<'py, PyList>> {
    let result_mod = py.import("app.models.result")?;
    let match_cls = result_mod.getattr("Match")?;
    let list = PyList::empty(py);

    for m in raw_matches {
        let kwargs = PyDict::new(py);
        kwargs.set_item("category", &m.category)?;
        kwargs.set_item("trigger", &m.trigger)?;
        kwargs.set_item("file", &m.file)?;
        kwargs.set_item("line_num", m.line_num)?;
        kwargs.set_item("code_snippet", &m.code_snippet)?;
        kwargs.set_item("severity", &m.severity)?;
        kwargs.set_item("score", m.score)?;
        let py_match = match_cls.call((), Some(&kwargs))?;
        list.append(py_match)?;
    }
    Ok(list)
}

#[pyclass]
pub struct RuleEngine {
    inner: rules::RuleEngine,
}

#[pymethods]
impl RuleEngine {
    #[new]
    pub fn new(rules_json: &str) -> PyResult<Self> {
        let inner = rules::RuleEngine::from_json(rules_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Evaluates rules on a JAR file directly in Rust without holding GIL.
    pub fn scan_jar<'py>(
        &self,
        py: Python<'py>,
        jar_path: &str,
        loader: &str,
    ) -> PyResult<Bound<'py, PyList>> {
        let raw_matches = py
            .detach(|| {
                let facts = jar::scan_jar(jar_path)?;
                Ok::<_, jar::JarScanError>(self.inner.evaluate(&facts, loader, true))
            })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        build_py_matches(py, &raw_matches)
    }

    /// Evaluates rules on a JAR file directly in Rust and returns Matches and EntropyMetrics
    /// WITHOUT the expensive overhead of marshalling hundreds of ClassFacts into Python.
    pub fn scan_jar_with_entropy<'py>(
        &self,
        py: Python<'py>,
        jar_path: &str,
        loader: &str,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyAny>)> {
        let (raw_matches, entropy) = py
            .detach(|| {
                let facts = jar::scan_jar(jar_path)?;
                let raw_matches = self.inner.evaluate(&facts, loader, true);
                Ok::<_, jar::JarScanError>((raw_matches, facts.entropy))
            })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let py_matches = build_py_matches(py, &raw_matches)?;
        let py_entropy = build_py_entropy(py, &entropy)?;
        Ok((py_matches, py_entropy))
    }

    /// Evaluates rules on a JAR file directly in Rust and returns both Matches and JarFacts.
    pub fn scan_jar_with_facts<'py>(
        &self,
        py: Python<'py>,
        jar_path: &str,
        loader: &str,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyAny>)> {
        let (raw_matches, facts) = py
            .detach(|| {
                let facts = jar::scan_jar(jar_path)?;
                let raw_matches = self.inner.evaluate(&facts, loader, true);
                Ok::<_, jar::JarScanError>((raw_matches, facts))
            })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let py_matches = build_py_matches(py, &raw_matches)?;
        let py_jar_facts = build_py_jar_facts(py, &facts)?;
        Ok((py_matches, py_jar_facts))
    }
}
