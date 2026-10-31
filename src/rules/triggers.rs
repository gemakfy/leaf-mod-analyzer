use super::matcher::is_gibberish_name;
use super::models::{CompiledMatcher, CompiledRule, MatcherFact};
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

fn find_matching_refs(
    haystack: &std::collections::HashSet<String>,
    needles: &[String],
) -> Option<String> {
    let mut matched: Vec<&str> = haystack
        .iter()
        .filter(|item| needles.iter().any(|needle| item.ends_with(needle)))
        .map(|s| s.as_str())
        .collect();
    if matched.is_empty() {
        return needles.first().cloned();
    }
    matched.sort_unstable();
    matched.dedup();
    let slice: Vec<&str> = matched.into_iter().take(2).collect();
    Some(slice.join(", "))
}

fn extract_string_evidence(facts: &ClassFactsData, matcher: &CompiledMatcher) -> Option<String> {
    if let Some(rx) = &matcher.regex {
        for s in &facts.strings {
            if let Ok(Some(m)) = rx.find(s) {
                let val = m.as_str();
                return if val.starts_with("http://") || val.starts_with("https://") {
                    Some(format!("URL: {val}"))
                } else {
                    Some(format!("literal: \"{val}\""))
                };
            }
        }
    } else if !matcher.any.is_empty() {
        for s in &facts.strings {
            if matcher.any.iter().any(|needle| s.contains(needle)) {
                return Some(format!("literal: \"{s}\""));
            }
        }
        return matcher.any.first().cloned();
    }
    None
}

fn extract_annotation_evidence(
    facts: &ClassFactsData,
    matcher: &CompiledMatcher,
) -> Option<String> {
    let mut matched_ann = Vec::new();
    for (type_name, elements) in &facts.annotations {
        if matcher.any.is_empty() || matcher.any.iter().any(|s| type_name.ends_with(s)) {
            let short_type = type_name.rsplit('/').next().unwrap_or(type_name);
            let clean_type = short_type.trim_end_matches(';');
            if let Some(rx) = &matcher.regex {
                let mut found_val = None;
                for vals in elements.values() {
                    for v in vals {
                        if rx.is_match(v).unwrap_or(false) {
                            found_val = Some(v.as_str());
                            break;
                        }
                    }
                    if found_val.is_some() {
                        break;
                    }
                }
                if let Some(val) = found_val {
                    matched_ann.push(format!("@{clean_type}({val})"));
                } else {
                    matched_ann.push(format!("@{clean_type}"));
                }
            } else {
                matched_ann.push(format!("@{clean_type}"));
            }
        }
    }
    matched_ann.sort_unstable();
    matched_ann.dedup();
    matched_ann
        .into_iter()
        .next()
        .or_else(|| matcher.any.first().cloned())
}

pub fn class_trigger(rule: &CompiledRule, facts: &ClassFactsData) -> String {
    let mut parts = Vec::new();
    for matcher in &rule.all_of {
        match matcher.fact {
            MatcherFact::MethodRef => {
                if let Some(ev) = find_matching_refs(&facts.method_refs, &matcher.any) {
                    parts.push(ev);
                }
            }
            MatcherFact::FieldRef => {
                if let Some(ev) = find_matching_refs(&facts.field_refs, &matcher.any) {
                    parts.push(ev);
                }
            }
            MatcherFact::ClassRef => {
                if let Some(ev) = find_matching_refs(&facts.class_refs, &matcher.any) {
                    parts.push(ev);
                }
            }
            MatcherFact::Annotation => {
                if let Some(ev) = extract_annotation_evidence(facts, matcher) {
                    parts.push(ev);
                }
            }
            MatcherFact::String => {
                if let Some(ev) = extract_string_evidence(facts, matcher) {
                    parts.push(ev);
                }
            }
            MatcherFact::FloatConstantMin => {
                if let Some(expected) = matcher.value {
                    let matched_c = facts
                        .float_constants
                        .iter()
                        .copied()
                        .find(|&c| (c - expected).abs() < 1e-4)
                        .unwrap_or(expected);
                    parts.push(format!("const: {matched_c}"));
                }
            }
            MatcherFact::NonAsciiName => {
                parts.push(format!(
                    "non-ASCII identifier: {}",
                    sanitize_path(&facts.class_name)
                ));
            }
            MatcherFact::MemberHomoglyphsMin => {
                let sample: Vec<&str> = facts
                    .member_homoglyphs
                    .iter()
                    .take(3)
                    .map(|s| s.as_str())
                    .collect();
                parts.push(format!("homoglyphs: {}", sample.join(", ")));
            }
            MatcherFact::CharConcat => {
                parts.push(format!("char concats: {}", facts.char_append_count));
            }
            _ => {
                if let Some(first) = matcher.any.first() {
                    parts.push(first.clone());
                }
            }
        }
    }
    let sanitized_cls = sanitize_path(&facts.class_name);
    if parts.is_empty() {
        return format!("{}: matched", sanitized_cls);
    }
    if parts.len() == 1 && parts[0].starts_with("URL: ") {
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
            MatcherFact::HiddenClassEntriesMin => {
                return format!(
                    "{} hidden class entries (bytecode files without .class extension)",
                    facts.hidden_class_entries
                );
            }
            MatcherFact::UnparsedClassesMin => {
                let sample: Vec<&str> = facts.unparsed.iter().take(3).map(|s| s.as_str()).collect();
                if sample.is_empty() {
                    return format!(
                        "{} unparsable/encrypted class entries",
                        facts.unparsed.len()
                    );
                }
                return format!(
                    "{} unparsable/encrypted class entries with corrupted bytecode headers (e.g. {})",
                    facts.unparsed.len(),
                    sample.join(", ")
                );
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
