use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleScope {
    Class,
    Jar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherFact {
    MethodRef,
    FieldRef,
    ClassRef,
    String,
    Annotation,
    CharConcat,
    MemberHomoglyphsMin,
    FloatConstantMin,
    ClassesMin,
    GibberishRatioMin,
    SingleLetterRatioMin,
    HiddenClassEntriesMin,
    UnparsedClassesMin,
    MissingEntrypointsMin,
    ShortNameRatioMin,
    ByteEntropyMaxMin,
    HighEntropyStringsMin,
    HighEntropyClassesMin,
    SwitchDensityMin,
    Unknown,
}

impl From<&str> for MatcherFact {
    fn from(s: &str) -> Self {
        match s {
            "method_ref" => Self::MethodRef,
            "field_ref" => Self::FieldRef,
            "class_ref" => Self::ClassRef,
            "string" => Self::String,
            "annotation" => Self::Annotation,
            "char_concat" => Self::CharConcat,
            "member_homoglyphs_min" => Self::MemberHomoglyphsMin,
            "float_constant_min" => Self::FloatConstantMin,
            "classes_min" => Self::ClassesMin,
            "gibberish_ratio_min" => Self::GibberishRatioMin,
            "single_letter_ratio_min" => Self::SingleLetterRatioMin,
            "hidden_class_entries_min" => Self::HiddenClassEntriesMin,
            "unparsed_classes_min" => Self::UnparsedClassesMin,
            "missing_entrypoints_min" => Self::MissingEntrypointsMin,
            "short_name_ratio_min" => Self::ShortNameRatioMin,
            "byte_entropy_max_min" => Self::ByteEntropyMaxMin,
            "high_entropy_strings_min" => Self::HighEntropyStringsMin,
            "high_entropy_classes_min" => Self::HighEntropyClassesMin,
            "switch_density_min" => Self::SwitchDensityMin,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawRule {
    #[serde(default = "default_class_scope")]
    pub scope: String,
    #[serde(default)]
    pub loaders: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_score")]
    pub score: i64,
    pub all_of: Vec<RawMatcher>,
}

fn default_class_scope() -> String {
    "class".to_string()
}

fn default_severity() -> String {
    "medium".to_string()
}

fn default_score() -> i64 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawMatcher {
    pub fact: String,
    #[serde(default)]
    pub any: Vec<String>,
    #[serde(default)]
    pub value: Option<f64>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub same_method: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledMatcher {
    pub fact: MatcherFact,
    pub any: Vec<String>,
    pub value: Option<f64>,
    pub pattern: Option<String>,
    pub regex: Option<fancy_regex::Regex>,
    pub same_method: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub scope: RuleScope,
    pub loaders: Vec<String>,
    pub severity: String,
    pub score: i64,
    pub all_of: Vec<CompiledMatcher>,
}

impl CompiledRule {
    #[inline]
    pub fn is_applicable(&self, loader: &str) -> bool {
        self.loaders.iter().any(|l| l == "any" || l == loader)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawMatch {
    pub category: String,
    pub trigger: String,
    pub file: String,
    pub line_num: usize,
    pub code_snippet: String,
    pub severity: String,
    pub score: i64,
}
