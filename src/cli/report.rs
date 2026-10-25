use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::loader::detect_loader;
use super::style::Style;
use crate::jar::models::{EntropyMetricsData, JarScanError};
use crate::jar::scan_jar;
use crate::rules::engine::RuleEngine;
use crate::rules::models::RawMatch;

#[derive(Serialize)]
pub struct SingleScanReport {
    pub file: String,
    pub file_size_bytes: u64,
    pub loader: String,
    pub classes_count: usize,
    pub status: String,
    pub score: i64,
    pub entropy: EntropyMetricsData,
    pub missing_entrypoints: Vec<String>,
    pub matches: Vec<RawMatch>,
}

pub fn collect_jars(target: &Path) -> Vec<PathBuf> {
    if target.is_file() {
        if target.extension().and_then(|s| s.to_str()) == Some("jar") {
            return vec![target.to_path_buf()];
        }
        return Vec::new();
    }

    let mut jars = Vec::new();
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("jar") {
                jars.push(p);
            }
        }
    }
    jars.sort();
    jars
}

pub fn scan_single_jar(
    jar_path: &Path,
    engine: &RuleEngine,
    forced_loader: Option<&str>,
) -> Result<SingleScanReport, JarScanError> {
    let path_str = jar_path.to_string_lossy();
    let facts = scan_jar(&path_str)?;
    let loader = forced_loader
        .map(|s| s.to_string())
        .unwrap_or_else(|| detect_loader(jar_path));

    let matches = engine.evaluate(&facts, &loader, true);
    let score = calculate_score(&matches);

    let status = if score >= 7 {
        "detected"
    } else if score >= 2 {
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
        status,
        score,
        entropy: facts.entropy,
        missing_entrypoints: facts.missing_entrypoints,
        matches,
    })
}

fn calculate_score(matches: &[RawMatch]) -> i64 {
    let mut event_scores: HashMap<(&str, &str), i64> = HashMap::new();
    for m in matches {
        let key = (m.category.as_str(), m.file.as_str());
        let current = event_scores.entry(key).or_insert(0);
        if m.score > *current {
            *current = m.score;
        }
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
    println!(
        " Size: {}  |  Classes: {}  |  Loader: {}",
        format_bytes(report.file_size_bytes),
        report.classes_count,
        report.loader
    );
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

    println!(
        "{}",
        style.dim("──────────────────────────────────────────────────────────────")
    );
    println!("{}", style.bold(" DETECTIONS"));

    if report.matches.is_empty() {
        println!(
            "   {} No suspicious bytecode patterns matched",
            style.green("✔")
        );
    } else {
        for m in &report.matches {
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

    println!(
        "{}",
        style.bold("══════════════════════════════════════════════════════════════")
    );
    match report.status.as_str() {
        "detected" => {
            println!(
                " VERDICT: {} (Total Score: {})",
                style.red("DETECTED / MALICIOUS"),
                report.score
            );
        }
        "suspicious" => {
            println!(
                " VERDICT: {} (Total Score: {})",
                style.yellow("SUSPICIOUS"),
                report.score
            );
        }
        _ => {
            println!(
                " VERDICT: {} (Total Score: {})",
                style.green("CLEAN"),
                report.score
            );
        }
    }
    println!(
        "{}",
        style.bold("══════════════════════════════════════════════════════════════")
    );
    println!();
}
