use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::loader::detect_loader;
use super::style::Style;
use crate::hashing::sha512_bytes;
use crate::jar::models::{EntropyMetricsData, JarScanError};
use crate::jar::{extract_embedded_jars, scan_jar, scan_jar_bytes};
use crate::rules::engine::RuleEngine;
use crate::rules::models::RawMatch;

#[derive(Serialize)]
pub struct SingleScanReport {
    pub file: String,
    pub file_size_bytes: u64,
    pub loader: String,
    pub classes_count: usize,
    pub unparsed_count: usize,
    pub status: String,
    pub score: i64,
    pub entropy: EntropyMetricsData,
    pub missing_entrypoints: Vec<String>,
    pub matches: Vec<RawMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub embedded: Vec<SingleScanReport>,
}

pub fn collect_jars(target: &Path) -> Vec<PathBuf> {
    if target.is_file() {
        return if is_jar_file(target) {
            vec![target.to_path_buf()]
        } else {
            Vec::new()
        };
    }

    let mut jars = Vec::new();
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            let p = entry.path();
            if is_jar_file(&p) {
                jars.push(p);
            }
        }
    }
    jars.sort();
    jars
}

#[inline]
fn is_jar_file(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("jar")
}

pub fn max_score_recursive(report: &SingleScanReport) -> i64 {
    let mut max = report.score;
    for child in &report.embedded {
        max = max.max(max_score_recursive(child));
    }
    max
}

fn scan_embedded_bytes_recursive(
    bytes: &[u8],
    engine: &RuleEngine,
    forced_loader: Option<&str>,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Vec<SingleScanReport> {
    if depth > 50 {
        return Vec::new();
    }
    let Ok(embedded_jars) = extract_embedded_jars(std::io::Cursor::new(bytes)) else {
        return Vec::new();
    };

    let mut reports = Vec::new();
    for (name, sub_bytes) in embedded_jars {
        if sub_bytes.is_empty() {
            continue;
        }
        let hash = sha512_bytes(&sub_bytes);
        if !visited.insert(hash) {
            continue;
        }

        let Ok(sub_facts) = scan_jar_bytes(&sub_bytes) else {
            continue;
        };

        let sub_loader = forced_loader.map(|s| s.to_string()).unwrap_or_else(|| {
            super::loader::detect_loader_from_reader(std::io::Cursor::new(&sub_bytes))
        });

        let sub_matches = engine.evaluate(&sub_facts, &sub_loader, true);
        let sub_score = calculate_score(&sub_matches);

        let nested =
            scan_embedded_bytes_recursive(&sub_bytes, engine, forced_loader, visited, depth + 1);

        let max_nested = nested.iter().map(max_score_recursive).max().unwrap_or(0);
        let effective_sub_score = sub_score.max(max_nested);

        let sub_status = if effective_sub_score >= 7 {
            "detected"
        } else if effective_sub_score >= 2 {
            "suspicious"
        } else {
            "clean"
        }
        .to_string();

        reports.push(SingleScanReport {
            file: name,
            file_size_bytes: sub_bytes.len() as u64,
            loader: sub_loader,
            classes_count: sub_facts.classes.len(),
            unparsed_count: sub_facts.unparsed.len(),
            status: sub_status,
            score: sub_score,
            entropy: sub_facts.entropy,
            missing_entrypoints: sub_facts.missing_entrypoints,
            matches: sub_matches,
            embedded: nested,
        });
    }

    reports
}

pub fn scan_single_jar(
    jar_path: &Path,
    engine: &RuleEngine,
    forced_loader: Option<&str>,
    deep: bool,
) -> Result<SingleScanReport, JarScanError> {
    let path_str = jar_path.to_string_lossy();
    let facts = scan_jar(&path_str)?;
    let loader = forced_loader
        .map(|s| s.to_string())
        .unwrap_or_else(|| detect_loader(jar_path));

    let matches = engine.evaluate(&facts, &loader, true);
    let score = calculate_score(&matches);

    let embedded = if deep {
        let mut visited = HashSet::new();
        if let Ok(root_bytes) = std::fs::read(jar_path) {
            visited.insert(sha512_bytes(&root_bytes));
            scan_embedded_bytes_recursive(&root_bytes, engine, forced_loader, &mut visited, 0)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let max_emb_score = embedded.iter().map(max_score_recursive).max().unwrap_or(0);
    let effective_score = score.max(max_emb_score);

    let status = if effective_score >= 7 {
        "detected"
    } else if effective_score >= 2 {
        "suspicious"
    } else {
        "clean"
    }
    .to_string();

    let file_size = std::fs::metadata(jar_path).map(|m| m.len()).unwrap_or(0);

    Ok(SingleScanReport {
        file: jar_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| path_str.to_string()),
        file_size_bytes: file_size,
        loader,
        classes_count: facts.classes.len(),
        unparsed_count: facts.unparsed.len(),
        status,
        score,
        entropy: facts.entropy,
        missing_entrypoints: facts.missing_entrypoints,
        matches,
        embedded,
    })
}

fn calculate_score(matches: &[RawMatch]) -> i64 {
    let mut event_scores: HashMap<(&str, &str), i64> = HashMap::new();
    for m in matches {
        let key = (m.category.as_str(), m.file.as_str());
        event_scores
            .entry(key)
            .and_modify(|current| *current = (*current).max(m.score))
            .or_insert(m.score);
    }
    event_scores.values().sum()
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn print_single_report(report: &SingleScanReport, style: &Style) {
    println!();
    println!(
        "{}",
        style.bold("══════════════════════════════════════════════════════════════")
    );
    println!(" {} {}", style.cyan("ANALYZING:"), style.bold(&report.file));
    let classes_display = if report.unparsed_count > 0 {
        format!(
            "{} ({} unparsed)",
            report.classes_count, report.unparsed_count
        )
    } else {
        report.classes_count.to_string()
    };
    println!(
        " Size: {}  |  Classes: {}  |  Loader: {}",
        format_bytes(report.file_size_bytes),
        classes_display,
        report.loader
    );
    print_telemetry(report, style);
    print_detections(&report.matches, style);
    if !report.embedded.is_empty() {
        print_embedded_reports(&report.embedded, style, 1);
    }
    print_verdict(report, style);
    println!();
}

fn print_embedded_reports(embedded: &[SingleScanReport], style: &Style, indent: usize) {
    if indent == 1 {
        println!(
            "{}",
            style.dim("──────────────────────────────────────────────────────────────")
        );
        println!("{}", style.bold(" EMBEDDED ARCHIVES (--deep)"));
    }

    for child in embedded {
        let tag = match child.status.as_str() {
            "detected" => style.red("[DETECTED]  "),
            "suspicious" => style.yellow("[SUSPICIOUS]"),
            _ => style.green("[CLEAN]     "),
        };
        let prefix = "  ".repeat(indent);
        println!(
            "{prefix}↳ {} {} (Score: {}, Classes: {})",
            tag,
            style.bold(&child.file),
            child.score,
            child.classes_count
        );
        for m in &child.matches {
            let mtag = match m.severity.to_lowercase().as_str() {
                "critical" => style.red("•"),
                "high" => style.red("•"),
                "medium" => style.yellow("•"),
                _ => style.cyan("•"),
            };
            println!(
                "{prefix}    {} {} (score: {}) -> {}",
                mtag,
                style.bold(&m.category),
                m.score,
                style.dim(&m.file)
            );
        }
        if !child.embedded.is_empty() {
            print_embedded_reports(&child.embedded, style, indent + 1);
        }
    }
}

fn print_telemetry(report: &SingleScanReport, style: &Style) {
    println!(
        "{}",
        style.dim("──────────────────────────────────────────────────────────────")
    );
    println!("{}", style.bold(" TELEMETRY & HEURISTICS"));
    println!(
        " • Entropy:          max {:.2} bits/byte, avg {:.2} bits/byte",
        report.entropy.byte_entropy_max, report.entropy.byte_entropy_avg
    );
    println!(
        " • Obfuscation:      {} (short names: {:.1}%, CFF density: {:.1}%)",
        report.entropy.obfuscation_type,
        report.entropy.short_name_ratio * 100.0,
        report.entropy.switch_density * 100.0
    );
    if report.entropy.high_entropy_strings > 0 {
        println!(
            " • Encrypted Pool:   {} high-entropy string literals",
            report.entropy.high_entropy_strings
        );
    }
    if !report.missing_entrypoints.is_empty() {
        println!(
            " • {} Missing entrypoints: {}",
            style.yellow("WARN:"),
            report.missing_entrypoints.join(", ")
        );
    }
}

fn print_detections(matches: &[RawMatch], style: &Style) {
    println!(
        "{}",
        style.dim("──────────────────────────────────────────────────────────────")
    );
    println!("{}", style.bold(" DETECTIONS"));

    if matches.is_empty() {
        println!(
            "   {} No suspicious bytecode patterns matched in root archive",
            style.green("✔")
        );
        return;
    }

    for m in matches {
        let tag = match m.severity.to_lowercase().as_str() {
            "critical" => style.red("[CRITICAL]"),
            "high" => style.red("[HIGH]    "),
            "medium" => style.yellow("[MEDIUM]  "),
            _ => style.cyan("[LOW]     "),
        };
        println!(
            "   {} {} (score: {}) -> {}",
            tag,
            style.bold(&m.category),
            m.score,
            style.dim(&m.file)
        );
        println!("            {}", style.dim(&m.trigger));
    }
}

fn print_verdict(report: &SingleScanReport, style: &Style) {
    println!(
        "{}",
        style.bold("══════════════════════════════════════════════════════════════")
    );
    let label = match report.status.as_str() {
        "detected" => style.red("DETECTED / MALICIOUS"),
        "suspicious" => style.yellow("SUSPICIOUS"),
        _ => style.green("CLEAN"),
    };
    let max_emb_score = report
        .embedded
        .iter()
        .map(max_score_recursive)
        .max()
        .unwrap_or(0);
    if max_emb_score > 0 {
        println!(
            " VERDICT: {} (Root Score: {}, Embedded Max: {})",
            label, report.score, max_emb_score
        );
    } else {
        println!(" VERDICT: {} (Total Score: {})", label, report.score);
    }
    println!(
        "{}",
        style.bold("══════════════════════════════════════════════════════════════")
    );
}
