use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;

use mod_analyzer_core::cli::banner::print_banner;
use mod_analyzer_core::cli::report::{
    collect_jars, print_single_report, scan_single_jar, SingleScanReport,
};
use mod_analyzer_core::cli::rules::load_rules;
use mod_analyzer_core::cli::style::Style;

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
    let start_time = Instant::now();

    if !cli.json {
        print_banner(&style);
    }

    let (engine, rules_count) = match load_rules(cli.rules.as_deref()) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("{} {err}", style.red("Error:"));
            std::process::exit(1);
        }
    };

    let jars = collect_jars(&cli.path);
    if jars.is_empty() {
        eprintln!(
            "{} No .jar files found at '{}'",
            style.yellow("Warning:"),
            cli.path.display()
        );
        std::process::exit(0);
    }

    let is_batch = jars.len() > 1;
    if !cli.json && is_batch {
        println!(
            "{} Scanning {} JAR files in {} (using {} rules)...",
            style.cyan("Leaf Mod Analyzer:"),
            style.bold(&jars.len().to_string()),
            style.dim(&cli.path.display().to_string()),
            rules_count
        );
        println!(
            "{}",
            style.dim(
                "─────────────────────────────────────────────────────────────────────────────"
            )
        );
    }

    let mut reports: Vec<SingleScanReport> = Vec::with_capacity(jars.len());
    let (mut clean_count, mut detected_count, mut suspicious_count) = (0, 0, 0);

    for jar in &jars {
        match scan_single_jar(jar, &engine, cli.loader.as_deref()) {
            Ok(report) => {
                match report.status.as_str() {
                    "detected" => detected_count += 1,
                    "suspicious" => suspicious_count += 1,
                    _ => clean_count += 1,
                }

                if !cli.json {
                    if is_batch {
                        print_batch_row(&report, &style);
                    } else {
                        print_single_report(&report, &style);
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

    if cli.json {
        print_json_reports(&reports, is_batch);
        return;
    }

    if is_batch {
        let elapsed = start_time.elapsed();
        println!(
            "{}",
            style.dim(
                "─────────────────────────────────────────────────────────────────────────────"
            )
        );
        println!(
            " {} Completed in {:.1}ms: {} clean, {} suspicious, {} detected",
            style.cyan("Summary:"),
            elapsed.as_secs_f64() * 1000.0,
            style.green(&clean_count.to_string()),
            style.yellow(&suspicious_count.to_string()),
            style.red(&detected_count.to_string())
        );
        println!();
    }
}

fn print_batch_row(report: &SingleScanReport, style: &Style) {
    let status_tag = match report.status.as_str() {
        "detected" => style.red("DETECTED  "),
        "suspicious" => style.yellow("SUSPICIOUS"),
        _ => style.green("CLEAN     "),
    };
    let name = format!("{:<36}", report.file);
    let display_name = if name.len() > 36 {
        format!("{}...", &name[..33])
    } else {
        name
    };
    let rules_info = if report.matches.is_empty() {
        format!("entropy: {:.2}", report.entropy.byte_entropy_max)
    } else {
        let mut cats: Vec<&str> = report.matches.iter().map(|m| m.category.as_str()).collect();
        cats.dedup();
        cats.join(", ")
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

fn print_json_reports(reports: &[SingleScanReport], is_batch: bool) {
    if is_batch {
        println!(
            "{}",
            serde_json::to_string_pretty(reports).unwrap_or_default()
        );
    } else if let Some(first) = reports.first() {
        println!(
            "{}",
            serde_json::to_string_pretty(first).unwrap_or_default()
        );
    }
}
