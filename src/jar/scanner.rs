use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use zip::ZipArchive;

use super::entrypoints::{find_missing_entrypoints, parse_entrypoints};
use super::entropy::build_entropy_metrics;
use super::models::{ClassFactsData, JarArchiveMetadata, JarFactsResult, JarScanError};
use crate::classfile::{self, is_homoglyph, RawClassData, JVM_MAGIC};

pub const MAX_CLASS_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_METADATA_BYTES: u64 = 1024 * 1024; // 1 MB limit for manifest / fabric.mod.json
pub const MAX_TOTAL_UNCOMPRESSED_BYTES: usize = 256 * 1024 * 1024; // 256 MB budget
pub const MAX_SCANNED_CLASSES: usize = 20_000;

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

fn collect_metadata_and_entries<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
) -> JarArchiveMetadata {
    let mut entry_names = HashSet::with_capacity(zip.len());
    let mut manifest_content = None;
    let mut fabric_mod_content = None;

    for i in 0..zip.len() {
        let Ok(file) = zip.by_index(i) else {
            continue;
        };
        let name = file.name().to_string();
        if name == "META-INF/MANIFEST.MF" {
            let mut buf = Vec::new();
            if file.take(MAX_METADATA_BYTES).read_to_end(&mut buf).is_ok() {
                manifest_content = Some(String::from_utf8_lossy(&buf).to_string());
            }
        } else if name == "fabric.mod.json" {
            let mut buf = Vec::new();
            if file.take(MAX_METADATA_BYTES).read_to_end(&mut buf).is_ok() {
                fabric_mod_content = Some(String::from_utf8_lossy(&buf).to_string());
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

fn read_candidate_class_entry(file: &mut zip::read::ZipFile<'_>) -> Option<Vec<u8>> {
    if file.is_dir() {
        return None;
    }
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() || &magic != JVM_MAGIC {
        return None;
    }

    let mut raw_bytes = Vec::with_capacity(4096);
    raw_bytes.extend_from_slice(&magic);
    file.take(MAX_CLASS_BYTES).read_to_end(&mut raw_bytes).ok()?;
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

        self.byte_entropies.push(crate::shannon_entropy(raw_bytes));

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

fn scan_zip_classes<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
) -> ClassScanAccumulator {
    let mut acc = ClassScanAccumulator::default();
    let mut total_uncompressed_bytes: usize = 0;

    for i in 0..zip.len() {
        if acc.classes.len() >= MAX_SCANNED_CLASSES
            || total_uncompressed_bytes >= MAX_TOTAL_UNCOMPRESSED_BYTES
        {
            break;
        }

        let Ok(mut file) = zip.by_index(i) else {
            continue;
        };
        let Some(raw_bytes) = read_candidate_class_entry(&mut file) else {
            continue;
        };

        total_uncompressed_bytes = total_uncompressed_bytes.saturating_add(raw_bytes.len());
        acc.record_class(file.name(), &raw_bytes);
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
