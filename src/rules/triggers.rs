use super::matcher::is_gibberish_name;
use super::models::{CompiledRule, MatcherFact};
use crate::jar::{ClassFactsData, JarFactsResult};

pub fn sanitize_path(name: &str) -> String {
    let mut cleaned = String::with_capacity(name.len());
    for ch in name.chars() {
        let code = ch as u32;
        if (32..127).contains(&code) || code > 159 {
            cleaned.push(ch);
        } else {
            cleaned.push('_');
        }
    }
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn class_trigger(rule: &CompiledRule, facts: &ClassFactsData) -> String {
    let mut parts = Vec::new();
    for matcher in &rule.all_of {
        if !matcher.any.is_empty() {
            let slice: Vec<&str> = matcher.any.iter().take(3).map(|s| s.as_str()).collect();
            parts.push(slice.join(" or "));
        } else if matcher.fact == MatcherFact::String {
            if let Some(rx) = &matcher.regex {
                for s in &facts.strings {
                    if let Ok(Some(m)) = rx.find(s) {
                        parts.push(format!("literal URL: {}", m.as_str()));
                        break;
                    }
                }
            }
        }
    }
    let sanitized_cls = sanitize_path(&facts.class_name);
    if parts.is_empty() {
        return format!("{}: matched", sanitized_cls);
    }
    if parts.len() == 1 && parts[0].starts_with("literal URL:") {
        return parts[0].clone();
    }
    format!("{}: {}", sanitized_cls, parts.join(" + "))
}

pub fn jar_trigger(rule: &CompiledRule, facts: &JarFactsResult) -> String {
    for matcher in &rule.all_of {
        match matcher.fact {
            MatcherFact::ByteEntropyMaxMin | MatcherFact::HighEntropyClassesMin => {
                return format!(
                    "High entropy: max {} bits/byte ({} packed classes)",
                    facts.entropy.byte_entropy_max, facts.entropy.high_entropy_classes
                );
            }
            MatcherFact::HighEntropyStringsMin => {
                return format!(
                    "Encrypted string pool: {} high-entropy strings",
                    facts.entropy.high_entropy_strings
                );
            }
            MatcherFact::ShortNameRatioMin => {
                let pct = (facts.entropy.short_name_ratio * 100.0) as i64;
                return format!("Aggressive renaming: {}% short class names", pct);
            }
            MatcherFact::SwitchDensityMin => {
                let pct = (facts.entropy.switch_density * 100.0) as i64;
                return format!("Control flow flattening: {}% switch dispatch methods", pct);
            }
            _ => {}
        }
    }

    let gibberish = facts
        .classes
        .iter()
        .filter(|c| is_gibberish_name(&c.simple_name))
        .count();
    let mut parts = vec![
        format!(
            "{}/{} machine-generated class names",
            gibberish,
            facts.classes.len()
        ),
        format!("{} unparsable", facts.unparsed.len()),
    ];
    if !facts.missing_entrypoints.is_empty() {
        let shown = facts
            .missing_entrypoints
            .iter()
            .take(3)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("declared but absent: {}", shown));
    }
    parts.join(", ")
}
