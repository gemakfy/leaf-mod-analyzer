use clap::Parser;
use std::path::{Path, PathBuf};
use std::time::Instant;

use mod_analyzer_core::cli::banner::print_banner;
use mod_analyzer_core::cli::report::{
    collect_jars, print_single_report, scan_single_jar, SingleScanReport,
};
use mod_analyzer_core::cli::rules::load_rules;
use mod_analyzer_core::cli::style::Style;
use mod_analyzer_core::rules::RuleEngine;

#[derive(Parser, Debug)]
#[command(
    name = "leaf-mod-analyzer",
    author = "Leaf Mod Analyzer Team",
    version = "0.1.0",
    about = "Leaf Mod Analyzer — Blazing fast static bytecode & security analyzer for Minecraft mods"
)]
struct Cli {
    /// Path to a .jar file or a directory with .jar files
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Optional path to custom rules (.json file or directory containing .json files)
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Target mod loader (fabric, forge, neoforge, quilt, or any). Auto-detected if omitted.
    #[arg(short, long)]
    loader: Option<String>,

    /// Output full scan results in JSON format
    #[arg(long)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();
    let style = Style::new();

    if let Err(err) = run(&cli, &style) {
        eprintln!("{} {err}", style.red("Error:"));
        std::process::exit(1);
    }
}

fn run(cli: &Cli, style: &Style) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    if !cli.json {
        print_banner(style);
    }

    let (engine, rules_count) =
        load_rules(cli.rules.as_deref()).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let jars = collect_jars(&cli.path);
    if jars.is_empty() {
        eprintln!(
            "{} No .jar files found at '{}'",
            style.yellow("Warning:"),
            cli.path.display()
        );
        return Ok(());
    }

    let is_batch = jars.len() > 1;
    if !cli.json && is_batch {
        print_batch_header(jars.len(), &cli.path, rules_count, style);
    }

    let (reports, stats) = execute_scan(&jars, &engine, cli, is_batch, style);

    if cli.json {
        print_json_reports(&reports, is_batch);
    } else if is_batch {
        print_batch_summary(start_time, &stats, style);
    }

    Ok(())
}

#[derive(Default)]
struct ScanStats {
    clean: usize,
    suspicious: usize,
    detected: usize,
}

impl ScanStats {
    fn record(&mut self, status: &str) {
        match status {
            "detected" => self.detected += 1,
            "suspicious" => self.suspicious += 1,
            _ => self.clean += 1,
        }
    }
}

fn print_batch_header(jar_count: usize, path: &Path, rules_count: usize, style: &Style) {
    println!(
        "{} Scanning {} JAR files in {} (using {} rules)...",
        style.cyan("Leaf Mod Analyzer:"),
        style.bold(&jar_count.to_string()),
        style.dim(&path.display().to_string()),
        rules_count
    );
    println!(
        "{}",
        style.dim("─────────────────────────────────────────────────────────────────────────────")
    );
}

fn execute_scan(
    jars: &[PathBuf],
    engine: &RuleEngine,
    cli: &Cli,
    is_batch: bool,
    style: &Style,
) -> (Vec<SingleScanReport>, ScanStats) {
    let mut reports = Vec::with_capacity(jars.len());
    let mut stats = ScanStats::default();

    for jar in jars {
        match scan_single_jar(jar, engine, cli.loader.as_deref()) {
            Ok(report) => {
                stats.record(&report.status);
                if !cli.json {
                    if is_batch {
                        print_batch_row(&report, style);
                    } else {
                        print_single_report(&report, style);
                    }
                }
                reports.push(report);
            }
            Err(e) => eprintln!(
                " [{}] Failed to scan {}: {e}",
                style.red("ERROR"),
                jar.display()
            ),
        }
    }

    (reports, stats)
}

fn print_batch_summary(start_time: Instant, stats: &ScanStats, style: &Style) {
    let elapsed = start_time.elapsed();
    println!(
        "{}",
        style.dim("─────────────────────────────────────────────────────────────────────────────")
    );
    println!(
        " {} Completed in {:.1}ms: {} clean, {} suspicious, {} detected",
        style.cyan("Summary:"),
        elapsed.as_secs_f64() * 1000.0,
        style.green(&stats.clean.to_string()),
        style.yellow(&stats.suspicious.to_string()),
        style.red(&stats.detected.to_string())
    );
    println!();
}

fn print_batch_row(report: &SingleScanReport, style: &Style) {
    let status_tag = match report.status.as_str() {
        "detected" => style.red("DETECTED  "),
        "suspicious" => style.yellow("SUSPICIOUS"),
        _ => style.green("CLEAN     "),
    };
    let display_name = format_file_column(&report.file);
    let rules_info = if report.matches.is_empty() {
        format!("entropy: {:.2}", report.entropy.byte_entropy_max)
    } else {
        let mut categories: Vec<&str> =
            report.matches.iter().map(|m| m.category.as_str()).collect();
        categories.sort_unstable();
        categories.dedup();
        categories.join(", ")
    };
    println!(
        " [{}] {} (score: {:>2}, classes: {:>4}) | {}",
        status_tag,
        style.bold(&display_name),
        report.score,
        report.classes_count,
        style.dim(&rules_info)
    );
}

fn format_file_column(filename: &str) -> String {
    if filename.len() > 36 {
        format!("{}...", &filename[..33])
    } else {
        format!("{filename:<36}")
    }
}

fn print_json_reports(reports: &[SingleScanReport], is_batch: bool) {
    let json_output = if is_batch {
        serde_json::to_string_pretty(reports)
    } else {
        serde_json::to_string_pretty(&reports.first())
    };
    println!("{}", json_output.unwrap_or_default());
}
