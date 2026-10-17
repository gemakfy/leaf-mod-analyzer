pub mod engine;
pub mod matcher;
pub mod models;
pub mod triggers;

pub use engine::{RuleCompileError, RuleEngine, MAX_MATCHES_PER_CATEGORY};
pub use matcher::{annotation_match, is_gibberish_name, suffix_match};
pub use models::{CompiledMatcher, CompiledRule, MatcherFact, RawMatch, RuleScope};
pub use triggers::sanitize_path;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jar::{ClassFactsData, EntropyMetricsData, JarFactsResult};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_is_gibberish_name_heuristics() {
        assert!(is_gibberish_name("12"));
        assert!(is_gibberish_name("x7"));
        assert!(is_gibberish_name("bcdf"));
        assert!(!is_gibberish_name("a")); // length 1
        assert!(!is_gibberish_name("something_long")); // length > 6
        assert!(!is_gibberish_name("Player")); // has vowels
    }

    #[test]
    fn test_sanitize_path_replaces_control_characters() {
        assert_eq!(sanitize_path("foo/\n\t\x01bar"), "foo/___bar");
        assert_eq!(sanitize_path("   "), "unknown");
        assert_eq!(sanitize_path("com/example/MyClass"), "com/example/MyClass");
    }

    #[test]
    fn test_suffix_match_logic() {
        let mut set = HashSet::new();
        set.insert("net/minecraft/entity/Entity.setBoundingBox".to_string());
        set.insert("net/minecraft/entity/Entity.inflate".to_string());

        let needles = vec!["setBoundingBox".to_string(), "func_1234".to_string()];
        assert!(suffix_match(&set, &needles));

        let non_matching = vec!["nonExistentMethod".to_string()];
        assert!(!suffix_match(&set, &non_matching));
        assert!(!suffix_match(&set, &[]));
    }

    #[test]
    fn test_rule_engine_from_json_and_eval_same_method() {
        let json = r#"{
            "Dropper_Download_Exec": {
                "scope": "class",
                "loaders": ["any"],
                "severity": "critical",
                "score": 10,
                "all_of": [
                    {
                        "fact": "method_ref",
                        "any": ["openStream", "openConnection"],
                        "same_method": true
                    },
                    {
                        "fact": "method_ref",
                        "any": ["exec", "start"],
                        "same_method": true
                    }
                ]
            }
        }"#;

        let engine = RuleEngine::from_json(json).unwrap();
        assert_eq!(engine.rules().len(), 1);

        let mut method_refs_by_method = HashMap::new();
        let mut m1 = HashSet::new();
        m1.insert("java/net/URL.openStream".to_string());
        m1.insert("java/lang/ProcessBuilder.start".to_string());
        method_refs_by_method.insert("downloadAndRun()V".to_string(), m1);

        let cf = ClassFactsData {
            class_name: "pkg/Malicious".to_string(),
            simple_name: "Malicious".to_string(),
            method_refs: HashSet::new(),
            field_refs: HashSet::new(),
            class_refs: HashSet::new(),
            strings: HashSet::new(),
            float_constants: Vec::new(),
            annotations: Vec::new(),
            member_names: HashSet::new(),
            char_append_count: 0,
            member_homoglyphs: Vec::new(),
            method_refs_by_method,
        };

        let jar_facts = JarFactsResult {
            classes: vec![cf],
            unparsed: Vec::new(),
            hidden_class_entries: 0,
            missing_entrypoints: Vec::new(),
            entropy: EntropyMetricsData {
                byte_entropy_avg: 0.0,
                byte_entropy_max: 0.0,
                high_entropy_classes: 0,
                high_entropy_strings: 0,
                short_name_ratio: 0.0,
                switch_density: 0.0,
                obfuscation_type: "none".to_string(),
            },
        };

        let matches = engine.evaluate(&jar_facts, "fabric", true);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, "Dropper_Download_Exec");
        assert_eq!(matches[0].file, "pkg/Malicious.java");
        assert_eq!(matches[0].score, 10);
    }
}
