use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use zip::ZipArchive;

use super::entropy::build_entropy_metrics;
use super::entrypoints::{find_missing_entrypoints, parse_entrypoints};
use super::models::{ClassFactsData, JarFactsResult, JarScanError};
use crate::classfile::{self, is_homoglyph, RawClassData, JVM_MAGIC};

pub fn scan_jar(jar_path: &str) -> Result<JarFactsResult, JarScanError> {
    let file = File::open(Path::new(jar_path))?;
    let reader = BufReader::with_capacity(64 * 1024, file);
    let mut zip = ZipArchive::new(reader)?;

    let mut entry_names = HashSet::with_capacity(zip.len());
    let mut manifest_content = None;
    let mut fabric_mod_content = None;
    let mut acc = ClassScanAccumulator::default();

    for i in 0..zip.len() {
        let Ok(mut file) = zip.by_index(i) else {
            continue;
        };
        let Ok(name_cow) = file.name() else {
            continue;
        };
        let is_dir = name_cow.ends_with('/');
        let name = name_cow.to_string();

        if !is_dir {
            entry_names.insert(name.clone());
        }

        if name == "META-INF/MANIFEST.MF" {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                manifest_content = Some(String::from_utf8_lossy(&buf).to_string());
            }
        } else if name == "fabric.mod.json" {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                fabric_mod_content = Some(String::from_utf8_lossy(&buf).to_string());
            }
        } else if let Some(raw_bytes) = read_candidate_class_entry(&mut file) {
            acc.record_class(&name, &raw_bytes);
        }
    }

    let declared_entrypoints =
        parse_entrypoints(fabric_mod_content.as_deref(), manifest_content.as_deref());
    let missing_entrypoints = find_missing_entrypoints(declared_entrypoints, &entry_names);

    let entropy = build_entropy_metrics(
        &acc.byte_entropies,
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

fn read_candidate_class_entry<R: Read>(file: &mut zip::read::ZipFile<'_, R>) -> Option<Vec<u8>> {
    if file.is_dir() {
        return None;
    }
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() || &magic != JVM_MAGIC {
        return None;
    }

    let mut raw_bytes = Vec::with_capacity(4096);
    raw_bytes.extend_from_slice(&magic);
    file.read_to_end(&mut raw_bytes).ok()?;
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
    fn record_class(&mut self, entry_name: &str, raw_bytes: &[u8]) {
        if !entry_name.ends_with(".class") {
            self.hidden_class_entries += 1;
        }

        self.byte_entropies.push(crate::entropy(raw_bytes));

        match classfile::parse_class(raw_bytes) {
            Some(data) => {
                let simple_stripped = data
                    .simple_name
                    .rsplit('$')
                    .next()
                    .unwrap_or(&data.simple_name);

                let is_numeric = !simple_stripped.is_empty()
                    && simple_stripped.chars().all(|c| c.is_ascii_digit());
                if simple_stripped.len() <= 2 && !is_numeric {
                    self.short_names += 1;
                }

                self.high_entropy_strings += data.encrypted_string_count;
                self.total_methods += data.total_methods;
                self.switch_methods += data.switch_methods;

                self.classes.push(build_class_facts_data(data));
            }
            None => {
                self.unparsed.push(entry_name.to_string());
            }
        }
    }
}

fn extract_homoglyphs(simple_name: &str, member_names: &HashSet<String>) -> Vec<String> {
    let simple_is_homoglyph = is_homoglyph(simple_name);
    let any_member_homoglyph = member_names.iter().any(|m| is_homoglyph(m));

    if !simple_is_homoglyph && !any_member_homoglyph {
        return Vec::new();
    }

    let mut homoglyphs = std::collections::BTreeSet::new();
    if simple_is_homoglyph {
        homoglyphs.insert(simple_name.to_string());
    }
    for m in member_names {
        if is_homoglyph(m) {
            homoglyphs.insert(m.clone());
        }
    }
    homoglyphs.into_iter().collect()
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
