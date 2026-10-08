use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use zip::ZipArchive;

use crate::classfile::{self, is_homoglyph, RawClassData};

const MAX_CLASS_BYTES: u64 = 32 * 1024 * 1024;

const SKIP_SUFFIXES: &[&str] = &[
    ".png", ".json", ".mcmeta", ".ogg", ".wav", ".fs", ".vsh", ".glsl",
    ".ttf", ".otf", ".txt", ".lang", ".toml", ".xml", ".properties",
    ".zip", ".jar", ".accesswidener", ".html", ".md", ".nbt",
    ".schematic", ".litematic",
];

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

pub fn scan_jar(jar_path: &str) -> Result<JarFactsResult, Box<dyn std::error::Error>> {
    let file = File::open(Path::new(jar_path))?;
    let reader = BufReader::new(file);
    let mut zip = ZipArchive::new(reader)?;

    let mut entry_names: HashSet<String> = HashSet::with_capacity(zip.len());
    let mut manifest_content: Option<String> = None;
    let mut fabric_mod_content: Option<String> = None;

    for i in 0..zip.len() {
        if let Ok(file) = zip.by_index(i) {
            let name = file.name().to_string();
            if name == "META-INF/MANIFEST.MF" {
                let mut content = String::new();
                let mut file_mut = file;
                let _ = file_mut.read_to_string(&mut content);
                manifest_content = Some(content);
            } else if name == "fabric.mod.json" {
                let mut content = String::new();
                let mut file_mut = file;
                let _ = file_mut.read_to_string(&mut content);
                fabric_mod_content = Some(content);
            }
            if !name.ends_with('/') {
                entry_names.insert(name);
            }
        }
    }

    let declared_entrypoints = parse_entrypoints(fabric_mod_content.as_deref(), manifest_content.as_deref());
    let mut missing_entrypoints: Vec<String> = declared_entrypoints
        .into_iter()
        .filter(|name| {
            let class_name = format!("{name}.class");
            !entry_names.contains(&class_name) && !entry_names.contains(name)
        })
        .collect();
    missing_entrypoints.sort();
    missing_entrypoints.dedup();

    let mut classes = Vec::new();
    let mut unparsed = Vec::new();
    let mut hidden_class_entries = 0;

    let mut byte_entropies: Vec<f64> = Vec::new();
    let mut short_names = 0;
    let mut high_entropy_strings = 0;
    let mut total_methods = 0;
    let mut switch_methods = 0;

    for i in 0..zip.len() {
        let mut file = match zip.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let name = file.name().to_string();
        if file.is_dir() || file.size() > MAX_CLASS_BYTES || should_skip_suffix(&name) {
            continue;
        }

        let mut raw_bytes = Vec::with_capacity(file.size() as usize);
        if file.read_to_end(&mut raw_bytes).is_err() {
            continue;
        }

        if raw_bytes.len() < 4 || &raw_bytes[0..4] != b"\xCA\xFE\xBA\xBE" {
            continue;
        }

        if !name.ends_with(".class") {
            hidden_class_entries += 1;
        }

        // Single pass: 1. Shannon entropy of raw classfile bytes
        let entropy_val = crate::shannon_entropy(&raw_bytes);
        byte_entropies.push(entropy_val);

        // Single pass: 2. Parse class facts, constant pool, and instructions
        match classfile::parse_class(&raw_bytes) {
            Some(data) => {
                let simple = data.simple_name.clone();
                let simple_stripped = simple.rsplit('$').next().unwrap_or(&simple);
                if simple_stripped.len() <= 2 {
                    short_names += 1;
                }

                high_entropy_strings += data.has_encrypted_strings;
                total_methods += data.total_methods;
                switch_methods += data.switch_methods;

                let facts = build_class_facts_data(data);
                classes.push(facts);
            }
            None => {
                unparsed.push(name);
            }
        }
    }

    let entropy = build_entropy_metrics(
        byte_entropies,
        classes.len(),
        short_names,
        high_entropy_strings,
        total_methods,
        switch_methods,
    );

    Ok(JarFactsResult {
        classes,
        unparsed,
        hidden_class_entries,
        missing_entrypoints,
        entropy,
    })
}

fn should_skip_suffix(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SKIP_SUFFIXES.iter().any(|&suffix| lower.ends_with(suffix))
}

fn build_class_facts_data(data: RawClassData) -> ClassFactsData {
    let mut homoglyphs = Vec::new();
    if is_homoglyph(&data.simple_name) {
        homoglyphs.push(data.simple_name.clone());
    }
    for m in &data.member_names {
        if is_homoglyph(m) {
            homoglyphs.push(m.clone());
        }
    }
    homoglyphs.sort();
    homoglyphs.dedup();

    let float_constants = data.float_constants;

    ClassFactsData {
        class_name: data.this_class,
        simple_name: data.simple_name,
        method_refs: data.method_refs,
        field_refs: data.field_refs,
        class_refs: data.class_refs,
        strings: data.strings,
        float_constants,
        annotations: data.annotations,
        member_names: data.member_names,
        char_append_count: data.char_append_count,
        member_homoglyphs: homoglyphs,
        method_refs_by_method: data.method_refs_by_method,
    }
}

fn parse_entrypoints(fabric_json: Option<&str>, manifest: Option<&str>) -> Vec<String> {
    let mut declared = Vec::new();

    if let Some(json_str) = fabric_json {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
            if let Some(ep_obj) = val.get("entrypoints").and_then(|v| v.as_object()) {
                for key in ["main", "client", "server", "preLaunch"] {
                    if let Some(arr) = ep_obj.get(key).and_then(|v| v.as_array()) {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                if !s.contains("::") && !s.is_empty() {
                                    let internal = s.replace('.', "/");
                                    if internal.contains('/') && !internal.ends_with('/') {
                                        declared.push(internal);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(mf) = manifest {
        let mut unfolded: Vec<String> = Vec::new();
        for line in mf.lines() {
            if (line.starts_with(' ') || line.starts_with('\t')) && !unfolded.is_empty() {
                let last = unfolded.last_mut().unwrap();
                last.push_str(&line[1..]);
            } else {
                unfolded.push(line.to_string());
            }
        }
        for line in unfolded {
            if let Some(rest) = line.strip_prefix("Fabric-Loom-Client-Only-Entries:") {
                for token in rest.split(|c: char| c == ';' || c == ',' || c.is_whitespace()) {
                    let trimmed = token.trim();
                    if let Some(stripped) = trimmed.strip_suffix(".class") {
                        declared.push(stripped.to_string());
                    }
                }
            }
        }
    }

    declared
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
        (entropies.iter().sum::<f64>() / total_len as f64 * 100.0).round() / 100.0
    } else {
        0.0
    };
    let max_entropy = if total_len > 0 {
        let max_val = entropies.iter().cloned().fold(f64::NAN, f64::max);
        (max_val * 100.0).round() / 100.0
    } else {
        0.0
    };
    let high_entropy_classes = entropies.iter().filter(|&&e| e >= 7.0).count();
    let short_ratio = if total_classes > 0 {
        (short_names as f64 / total_classes as f64 * 1000.0).round() / 1000.0
    } else {
        0.0
    };
    let switch_density = if total_methods > 0 {
        (switch_methods as f64 / total_methods as f64 * 1000.0).round() / 1000.0
    } else {
        0.0
    };

    let obfuscation_type = if high_entropy_classes > 0 {
        "packed"
    } else if high_entropy_strings >= 5 {
        "encrypted"
    } else if short_ratio >= 0.35 {
        "renamed"
    } else {
        "none"
    };

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
