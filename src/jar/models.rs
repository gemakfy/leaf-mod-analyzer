use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, thiserror::Error)]
pub enum JarScanError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, Clone)]
pub struct ClassFactsData {
    pub class_name: String,
    pub simple_name: String,
    pub method_refs: HashSet<String>,
    pub field_refs: HashSet<String>,
    pub class_refs: HashSet<String>,
    pub strings: HashSet<String>,
    pub float_constants: Vec<f64>,
    pub annotations: Vec<(String, HashMap<String, Vec<String>>)>,
    pub member_names: HashSet<String>,
    pub char_append_count: usize,
    pub member_homoglyphs: Vec<String>,
    pub method_refs_by_method: HashMap<String, HashSet<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyMetricsData {
    pub byte_entropy_avg: f64,
    pub byte_entropy_max: f64,
    pub high_entropy_classes: usize,
    pub high_entropy_strings: usize,
    pub short_name_ratio: f64,
    pub switch_density: f64,
    pub obfuscation_type: String,
}

#[derive(Debug, Clone)]
pub struct JarFactsResult {
    pub classes: Vec<ClassFactsData>,
    pub unparsed: Vec<String>,
    pub hidden_class_entries: usize,
    pub missing_entrypoints: Vec<String>,
    pub entropy: EntropyMetricsData,
}
