use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use zip::ZipArchive;

use crate::classfile::{self, is_homoglyph, RawClassData, JVM_MAGIC};

const MAX_CLASS_BYTES: u64 = 32 * 1024 * 1024;

const SKIP_SUFFIXES: &[&str] = &[
    ".png", ".json", ".mcmeta", ".ogg", ".wav", ".fs", ".vsh", ".glsl",
    ".ttf", ".otf", ".txt", ".lang", ".toml", ".xml", ".properties",
    ".zip", ".jar", ".accesswidener", ".html", ".md", ".nbt",
    ".schematic", ".litematic",
];

#[derive(Debug, thiserror::Error)]
pub enum JarScanError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
}

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

pub struct EntropyMetricsData {
    pub byte_entropy_avg: f64,
    pub byte_entropy_max: f64,
    pub high_entropy_classes: usize,
    pub high_entropy_strings: usize,
    pub short_name_ratio: f64,
    pub switch_density: f64,
    pub obfuscation_type: String,
}

pub struct JarFactsResult {
    pub classes: Vec<ClassFactsData>,
    pub unparsed: Vec<String>,
    pub hidden_class_entries: usize,
    pub missing_entrypoints: Vec<String>,
    pub entropy: EntropyMetricsData,
}

pub fn scan_jar(jar_path: &str) -> Result<JarFactsResult, JarScanError> {
    let file = File::open(Path::new(jar_path))?;
    let reader = BufReader::new(file);
    let mut zip = ZipArchive::new(reader)?;

    let meta = collect_metadata_and_entries(&mut zip);
    let declared_entrypoints = parse_entrypoints(
        meta.fabric_mod_content.as_deref(),
        meta.manifest_content.as_deref(),
    );
    let missing_entrypoints = find_missing_entrypoints(declared_entrypoints, &meta.entry_names);

    let acc = scan_zip_classes(&mut zip);
    let entropy = build_entropy_metrics(
        acc.byte_entropies,
        acc.classes.len(),
        acc.short_names,
        acc.high_entropy_strings,
        acc.total_methods,
        acc.switch_methods,
    );

    Ok(JarFactsResult {
        classes: acc.classes,
        unparsed: acc.unparsed,
        hidden_class_entries: acc.hidden_class_entries,
        missing_entrypoints,
        entropy,
    })
}

struct JarArchiveMetadata {
    entry_names: HashSet<String>,
    manifest_content: Option<String>,
    fabric_mod_content: Option<String>,
}

fn collect_metadata_and_entries<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
) -> JarArchiveMetadata {
    let mut entry_names = HashSet::with_capacity(zip.len());
    let mut manifest_content = None;
    let mut fabric_mod_content = None;

    for i in 0..zip.len() {
        let Ok(mut file) = zip.by_index(i) else {
            continue;
        };
        let name = file.name().to_string();
        if name == "META-INF/MANIFEST.MF" {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                manifest_content = Some(content);
            }
        } else if name == "fabric.mod.json" {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                fabric_mod_content = Some(content);
            }
        }
        if !name.ends_with('/') {
            entry_names.insert(name);
        }
    }

    JarArchiveMetadata {
        entry_names,
        manifest_content,
        fabric_mod_content,
    }
}

fn find_missing_entrypoints(
    declared: Vec<String>,
    entry_names: &HashSet<String>,
) -> Vec<String> {
    let mut missing: Vec<String> = declared
        .into_iter()
        .filter(|name| {
            let class_name = format!("{name}.class");
            !entry_names.contains(&class_name) && !entry_names.contains(name)
        })
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

fn should_skip_suffix(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SKIP_SUFFIXES.iter().any(|&suffix| lower.ends_with(suffix))
}

fn read_candidate_class_entry(file: &mut zip::read::ZipFile<'_>) -> Option<Vec<u8>> {
    let name = file.name();
    if file.is_dir() || file.size() > MAX_CLASS_BYTES || should_skip_suffix(name) {
        return None;
    }
    let mut raw_bytes = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut raw_bytes).ok()?;
    if raw_bytes.len() < 4 || &raw_bytes[0..4] != JVM_MAGIC {
        return None;
    }
    Some(raw_bytes)
}

#[derive(Default)]
struct ClassScanAccumulator {
    classes: Vec<ClassFactsData>,
    unparsed: Vec<String>,
    hidden_class_entries: usize,
    byte_entropies: Vec<f64>,
    short_names: usize,
    high_entropy_strings: usize,
    total_methods: usize,
    switch_methods: usize,
}

impl ClassScanAccumulator {
    fn record_class(&mut self, entry_name: String, raw_bytes: &[u8]) {
        if !entry_name.ends_with(".class") {
            self.hidden_class_entries += 1;
        }

        self.byte_entropies.push(crate::shannon_entropy(raw_bytes));

        match classfile::parse_class(raw_bytes) {
            Some(data) => {
                let simple_stripped = data
                    .simple_name
                    .rsplit('$')
                    .next()
                    .unwrap_or(&data.simple_name);
                if simple_stripped.len() <= 2 {
                    self.short_names += 1;
                }

                self.high_entropy_strings += data.has_encrypted_strings;
                self.total_methods += data.total_methods;
                self.switch_methods += data.switch_methods;

                self.classes.push(build_class_facts_data(data));
            }
            None => {
                self.unparsed.push(entry_name);
            }
        }
    }
}

fn scan_zip_classes<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
) -> ClassScanAccumulator {
    let mut acc = ClassScanAccumulator::default();
    for i in 0..zip.len() {
        let Ok(mut file) = zip.by_index(i) else {
            continue;
        };
        let Some(raw_bytes) = read_candidate_class_entry(&mut file) else {
            continue;
        };
        acc.record_class(file.name().to_string(), &raw_bytes);
    }
    acc
}

fn extract_homoglyphs(simple_name: &str, member_names: &HashSet<String>) -> Vec<String> {
    let mut homoglyphs = Vec::new();
    if is_homoglyph(simple_name) {
        homoglyphs.push(simple_name.to_string());
    }
    for m in member_names {
        if is_homoglyph(m) {
            homoglyphs.push(m.clone());
        }
    }
    homoglyphs.sort();
    homoglyphs.dedup();
    homoglyphs
}

pub fn build_class_facts_data(data: RawClassData) -> ClassFactsData {
    let member_homoglyphs = extract_homoglyphs(&data.simple_name, &data.member_names);

    ClassFactsData {
        class_name: data.this_class,
        simple_name: data.simple_name,
        method_refs: data.method_refs,
        field_refs: data.field_refs,
        class_refs: data.class_refs,
        strings: data.strings,
        float_constants: data.float_constants,
        annotations: data.annotations,
        member_names: data.member_names,
        char_append_count: data.char_append_count,
        member_homoglyphs,
        method_refs_by_method: data.method_refs_by_method,
    }
}

fn parse_fabric_entrypoint_value(s: &str) -> Option<String> {
    if s.is_empty() || s.contains("::") {
        return None;
    }
    let internal = s.replace('.', "/");
    if internal.contains('/') && !internal.ends_with('/') {
        Some(internal)
    } else {
        None
    }
}

fn parse_fabric_entrypoints(fabric_json: &str, declared: &mut Vec<String>) {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(fabric_json) else {
        return;
    };
    let Some(ep_obj) = val.get("entrypoints").and_then(|v| v.as_object()) else {
        return;
    };

    const ENTRYPOINT_KEYS: [&str; 4] = ["main", "client", "server", "preLaunch"];
    for key in ENTRYPOINT_KEYS {
        let Some(arr) = ep_obj.get(key).and_then(|v| v.as_array()) else {
            continue;
        };
        for item in arr {
            if let Some(s) = item.as_str().and_then(parse_fabric_entrypoint_value) {
                declared.push(s);
            }
        }
    }
}

fn unfold_manifest_lines(manifest: &str) -> Vec<String> {
    let mut unfolded: Vec<String> = Vec::new();
    for line in manifest.lines() {
        if (line.starts_with(' ') || line.starts_with('\t')) && !unfolded.is_empty() {
            let last = unfolded.last_mut().unwrap();
            last.push_str(&line[1..]);
        } else {
            unfolded.push(line.to_string());
        }
    }
    unfolded
}

fn parse_manifest_entrypoints(manifest: &str, declared: &mut Vec<String>) {
    for line in unfold_manifest_lines(manifest) {
        let Some(rest) = line.strip_prefix("Fabric-Loom-Client-Only-Entries:") else {
            continue;
        };
        for token in rest.split(|c: char| c == ';' || c == ',' || c.is_whitespace()) {
            let trimmed = token.trim();
            if let Some(stripped) = trimmed.strip_suffix(".class") {
                declared.push(stripped.to_string());
            }
        }
    }
}

fn parse_entrypoints(fabric_json: Option<&str>, manifest: Option<&str>) -> Vec<String> {
    let mut declared = Vec::new();
    if let Some(json_str) = fabric_json {
        parse_fabric_entrypoints(json_str, &mut declared);
    }
    if let Some(mf) = manifest {
        parse_manifest_entrypoints(mf, &mut declared);
    }
    declared
}

fn round_to(val: f64, decimals: u32) -> f64 {
    let factor = 10_f64.powi(decimals as i32);
    (val * factor).round() / factor
}

fn classify_obfuscation(
    high_entropy_classes: usize,
    high_entropy_strings: usize,
    short_ratio: f64,
) -> &'static str {
    if high_entropy_classes > 0 {
        "packed"
    } else if high_entropy_strings >= 5 {
        "encrypted"
    } else if short_ratio >= 0.35 {
        "renamed"
    } else {
        "none"
    }
}

fn build_entropy_metrics(
    entropies: Vec<f64>,
    total_classes: usize,
    short_names: usize,
    high_entropy_strings: usize,
    total_methods: usize,
    switch_methods: usize,
) -> EntropyMetricsData {
    let total_len = entropies.len();
    let avg_entropy = if total_len > 0 {
        round_to(entropies.iter().sum::<f64>() / total_len as f64, 2)
    } else {
        0.0
    };
    let max_entropy = if total_len > 0 {
        let max_val = entropies.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        round_to(max_val, 2)
    } else {
        0.0
    };
    let high_entropy_classes = entropies.iter().filter(|&&e| e >= 7.0).count();
    let short_ratio = if total_classes > 0 {
        round_to(short_names as f64 / total_classes as f64, 3)
    } else {
        0.0
    };
    let switch_density = if total_methods > 0 {
        round_to(switch_methods as f64 / total_methods as f64, 3)
    } else {
        0.0
    };

    let obfuscation_type = classify_obfuscation(high_entropy_classes, high_entropy_strings, short_ratio);

    EntropyMetricsData {
        byte_entropy_avg: avg_entropy,
        byte_entropy_max: max_entropy,
        high_entropy_classes,
        high_entropy_strings,
        short_name_ratio: short_ratio,
        switch_density,
        obfuscation_type: obfuscation_type.to_string(),
    }
}
