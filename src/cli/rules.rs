use std::collections::BTreeMap;
use std::path::Path;

use crate::rules::engine::RuleEngine;
use crate::rules::models::RawRule;

pub const DEFAULT_RULES_JSON: &str = include_str!("../default_rules.json");

pub fn load_rules(custom_path: Option<&Path>) -> Result<(RuleEngine, usize), String> {
    match custom_path {
        None => {
            let engine = RuleEngine::from_json(DEFAULT_RULES_JSON)
                .map_err(|e| format!("Failed to parse default rules: {e}"))?;
            let count = engine.rules().len();
            Ok((engine, count))
        }
        Some(path) => {
            if path.is_file() {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
                let engine = RuleEngine::from_json(&content)
                    .map_err(|e| format!("Failed to compile rules from {}: {e}", path.display()))?;
                let count = engine.rules().len();
                Ok((engine, count))
            } else if path.is_dir() {
                let mut merged: BTreeMap<String, RawRule> = BTreeMap::new();
                collect_json_rules(path, &mut merged)?;
                let engine = RuleEngine::from_raw_rules(merged).map_err(|e| {
                    format!(
                        "Failed to compile merged rules from {}: {e}",
                        path.display()
                    )
                })?;
                let count = engine.rules().len();
                Ok((engine, count))
            } else {
                Err(format!("Rules path not found: {}", path.display()))
            }
        }
    }
}

fn collect_json_rules(dir: &Path, merged: &mut BTreeMap<String, RawRule>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("Failed to read dir {}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_json_rules(&p, merged)?;
        } else if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = std::fs::read_to_string(&p)
                .map_err(|e| format!("Failed to read {}: {e}", p.display()))?;
            let rules: BTreeMap<String, RawRule> = serde_json::from_str(&content)
                .map_err(|e| format!("Error in rule file {}: {e}", p.display()))?;
            for (k, v) in rules {
                merged.insert(k, v);
            }
        }
    }
    Ok(())
}
