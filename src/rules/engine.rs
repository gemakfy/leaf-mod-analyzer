use std::collections::{BTreeMap, HashMap};

use super::matcher::class_matchers_hold;
use super::models::{
    CompiledMatcher, CompiledRule, MatcherFact, RawMatch, RawRule, RuleScope,
};
use super::triggers::{class_trigger, jar_trigger, sanitize_path};
use crate::jar::JarFactsResult;

pub const MAX_MATCHES_PER_CATEGORY: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum RuleCompileError {
    #[error("Rule '{0}' must declare at least one matcher in all_of")]
    EmptyAllOf(String),
    #[error("Invalid regex in pattern '{0}': {1}")]
    RegexError(String, Box<fancy_regex::Error>),
    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        Self { rules }
    }

    pub fn from_json(json_str: &str) -> Result<Self, RuleCompileError> {
        let raw_rules: BTreeMap<String, RawRule> = serde_json::from_str(json_str)?;
        let mut compiled = Vec::with_capacity(raw_rules.len());

        for (name, raw) in raw_rules {
            if raw.all_of.is_empty() {
                return Err(RuleCompileError::EmptyAllOf(name));
            }
            let scope = match raw.scope.as_str() {
                "jar" => RuleScope::Jar,
                _ => RuleScope::Class,
            };

            let mut matchers = Vec::with_capacity(raw.all_of.len());
            for m in raw.all_of {
                let fact = MatcherFact::from(m.fact.as_str());
                let regex = if let Some(ref pat) = m.pattern {
                    Some(fancy_regex::Regex::new(pat).map_err(|e| {
                        RuleCompileError::RegexError(pat.clone(), Box::new(e))
                    })?)
                } else {
                    None
                };
                matchers.push(CompiledMatcher {
                    fact,
                    any: m.any,
                    value: m.value,
                    pattern: m.pattern,
                    regex,
                    same_method: m.same_method,
                });
            }

            compiled.push(CompiledRule {
                name,
                scope,
                loaders: raw.loaders,
                severity: raw.severity,
                score: raw.score,
                all_of: matchers,
            });
        }

        Ok(Self { rules: compiled })
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    pub fn evaluate(
        &self,
        facts: &JarFactsResult,
        loader: &str,
        target_ext_java: bool,
    ) -> Vec<RawMatch> {
        let mut matches = Vec::new();
        let mut per_category = HashMap::new();

        for rule in &self.rules {
            if !rule.is_applicable(loader) {
                continue;
            }

            match rule.scope {
                RuleScope::Jar => {
                    if rule.all_of.iter().all(|m| m.holds_for_jar(facts)) {
                        let trigger = jar_trigger(rule, facts);
                        emit_match(
                            &mut matches,
                            &mut per_category,
                            rule,
                            "archive",
                            1,
                            trigger,
                            target_ext_java,
                        );
                    }
                }
                RuleScope::Class => {
                    for class_facts in &facts.classes {
                        if !class_matchers_hold(rule, class_facts) {
                            continue;
                        }
                        let trigger = class_trigger(rule, class_facts);
                        emit_match(
                            &mut matches,
                            &mut per_category,
                            rule,
                            &class_facts.class_name,
                            1,
                            trigger,
                            target_ext_java,
                        );
                        if per_category.get(rule.name.as_str()).copied().unwrap_or(0)
                            >= MAX_MATCHES_PER_CATEGORY
                        {
                            break;
                        }
                    }
                }
            }
        }

        matches
    }
}

fn emit_match<'a>(
    matches: &mut Vec<RawMatch>,
    per_category: &mut HashMap<&'a str, usize>,
    rule: &'a CompiledRule,
    file_name: &str,
    line: usize,
    trigger: String,
    target_ext_java: bool,
) {
    let count = per_category.entry(rule.name.as_str()).or_insert(0);
    if *count >= MAX_MATCHES_PER_CATEGORY {
        return;
    }
    *count += 1;

    let sanitized = sanitize_path(file_name);
    let target_file = if sanitized == "archive" {
        "archive".to_string()
    } else if target_ext_java {
        let base = sanitized.strip_suffix(".class").unwrap_or(&sanitized);
        format!("{}.java", base)
    } else if sanitized.ends_with(".class") {
        sanitized
    } else {
        format!("{}.class", sanitized)
    };

    matches.push(RawMatch {
        category: rule.name.clone(),
        trigger,
        file: target_file,
        line_num: line.max(1),
        code_snippet: String::new(),
        severity: rule.severity.clone(),
        score: rule.score.max(0),
    });
}
