use std::collections::HashSet;

use super::models::{CompiledMatcher, CompiledRule, MatcherFact};
use crate::jar::{ClassFactsData, JarFactsResult};

pub fn is_gibberish_name(name: &str) -> bool {
    let char_count = name.chars().count();
    if !(2..=6).contains(&char_count) {
        return false;
    }
    if name.chars().any(|ch| ch.is_ascii_digit()) {
        return true;
    }
    !name.chars().any(|ch| {
        matches!(
            ch,
            'a' | 'e' | 'i' | 'o' | 'u' | 'y' | 'A' | 'E' | 'I' | 'O' | 'U' | 'Y'
        )
    })
}

pub fn suffix_match(haystack: &HashSet<String>, needles: &[String]) -> bool {
    if needles.is_empty() || haystack.is_empty() {
        return false;
    }
    haystack
        .iter()
        .any(|ref_str| needles.iter().any(|needle| ref_str.ends_with(needle)))
}

pub fn annotation_match(
    annotations: &[(String, std::collections::HashMap<String, Vec<String>>)],
    type_suffixes: &[String],
    rx: Option<&fancy_regex::Regex>,
) -> bool {
    for (type_name, elements) in annotations {
        if !type_suffixes
            .iter()
            .any(|suffix| type_name.ends_with(suffix))
        {
            continue;
        }
        let Some(rx) = rx else {
            return true;
        };
        for values in elements.values() {
            if values.iter().any(|v| rx.is_match(v).unwrap_or(false)) {
                return true;
            }
        }
    }
    false
}

impl CompiledMatcher {
    pub fn holds_for_class(&self, facts: &ClassFactsData) -> bool {
        match self.fact {
            MatcherFact::MethodRef if !self.same_method => {
                suffix_match(&facts.method_refs, &self.any)
            }
            MatcherFact::FieldRef => suffix_match(&facts.field_refs, &self.any),
            MatcherFact::ClassRef => suffix_match(&facts.class_refs, &self.any),
            MatcherFact::String => {
                let Some(rx) = &self.regex else {
                    return false;
                };
                facts
                    .strings
                    .iter()
                    .any(|s| rx.is_match(s).unwrap_or(false))
            }
            MatcherFact::Annotation => {
                annotation_match(&facts.annotations, &self.any, self.regex.as_ref())
            }
            MatcherFact::CharConcat => {
                let threshold = self.value.unwrap_or(60.0) as usize;
                facts.char_append_count >= threshold
            }
            MatcherFact::MemberHomoglyphsMin => {
                let threshold = self.value.unwrap_or(0.0) as usize;
                facts.member_homoglyphs.len() >= threshold
            }
            MatcherFact::FloatConstantMin => {
                let threshold = self.value.unwrap_or(0.0);
                facts.float_constants.iter().any(|c| c.abs() >= threshold)
            }
            _ => false,
        }
    }

    fn holds_for_jar_entropy(&self, facts: &JarFactsResult) -> bool {
        match self.fact {
            MatcherFact::ShortNameRatioMin => {
                facts.entropy.short_name_ratio >= self.value.unwrap_or(0.0)
            }
            MatcherFact::ByteEntropyMaxMin => {
                facts.entropy.byte_entropy_max >= self.value.unwrap_or(0.0)
            }
            MatcherFact::HighEntropyStringsMin => {
                let threshold = self.value.unwrap_or(0.0) as usize;
                facts.entropy.high_entropy_strings >= threshold
            }
            MatcherFact::HighEntropyClassesMin => {
                let threshold = self.value.unwrap_or(0.0) as usize;
                facts.entropy.high_entropy_classes >= threshold
            }
            MatcherFact::SwitchDensityMin => {
                facts.entropy.switch_density >= self.value.unwrap_or(0.0)
            }
            _ => false,
        }
    }

    pub fn holds_for_jar(&self, facts: &JarFactsResult) -> bool {
        match self.fact {
            MatcherFact::ClassesMin => {
                let threshold = self.value.unwrap_or(0.0) as usize;
                facts.classes.len() >= threshold
            }
            MatcherFact::GibberishRatioMin => {
                if facts.classes.is_empty() {
                    return false;
                }
                let gibberish = facts
                    .classes
                    .iter()
                    .filter(|c| is_gibberish_name(&c.simple_name))
                    .count();
                let ratio = (gibberish as f64) / (facts.classes.len() as f64);
                ratio >= self.value.unwrap_or(0.0)
            }
            MatcherFact::SingleLetterRatioMin => {
                if facts.classes.is_empty() {
                    return false;
                }
                let singles = facts
                    .classes
                    .iter()
                    .filter(|c| c.simple_name.len() == 1)
                    .count();
                let ratio = (singles as f64) / (facts.classes.len() as f64);
                ratio >= self.value.unwrap_or(0.0)
            }
            MatcherFact::HiddenClassEntriesMin => {
                let threshold = self.value.unwrap_or(0.0) as usize;
                facts.hidden_class_entries >= threshold
            }
            MatcherFact::UnparsedClassesMin => {
                let threshold = self.value.unwrap_or(0.0) as usize;
                facts.unparsed.len() >= threshold
            }
            MatcherFact::MissingEntrypointsMin => {
                let threshold = self.value.unwrap_or(1.0) as usize;
                facts.missing_entrypoints.len() >= threshold
            }
            _ => self.holds_for_jar_entropy(facts),
        }
    }
}

pub fn class_matchers_hold(rule: &CompiledRule, facts: &ClassFactsData) -> bool {
    let same_method: Vec<&CompiledMatcher> = rule
        .all_of
        .iter()
        .filter(|m| m.same_method && m.fact == MatcherFact::MethodRef)
        .collect();

    let other_hold = rule
        .all_of
        .iter()
        .filter(|m| !(m.same_method && m.fact == MatcherFact::MethodRef))
        .all(|m| m.holds_for_class(facts));

    if !other_hold {
        return false;
    }
    if same_method.is_empty() {
        return true;
    }
    facts
        .method_refs_by_method
        .values()
        .any(|refs| same_method.iter().all(|m| suffix_match(refs, &m.any)))
}
