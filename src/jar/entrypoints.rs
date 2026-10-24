use std::collections::HashSet;

pub fn parse_fabric_entrypoint_value(s: &str) -> Option<String> {
    let class_part = s.split("::").next()?.trim();
    if class_part.is_empty() {
        return None;
    }
    let internal = class_part.replace('.', "/");
    (!internal.ends_with('/')).then_some(internal)
}

pub fn parse_fabric_entrypoints(fabric_json: &str, declared: &mut Vec<String>) {
    let clean_json = fabric_json.strip_prefix('\u{FEFF}').unwrap_or(fabric_json);
    let Ok(val) = serde_json::from_str::<serde_json::Value>(clean_json) else {
        return;
    };
    let Some(ep_obj) = val.get("entrypoints").and_then(|v| v.as_object()) else {
        return;
    };

    for (_key, val) in ep_obj {
        if let Some(arr) = val.as_array() {
            for item in arr {
                let candidate = item
                    .as_str()
                    .or_else(|| item.get("value").and_then(|v| v.as_str()));
                if let Some(s) = candidate.and_then(parse_fabric_entrypoint_value) {
                    declared.push(s);
                }
            }
        } else if let Some(s) = val.as_str() {
            if let Some(ep) = parse_fabric_entrypoint_value(s) {
                declared.push(ep);
            }
        }
    }
}

pub fn unfold_manifest_lines(manifest: &str) -> Vec<String> {
    let mut unfolded: Vec<String> = Vec::new();
    for line in manifest.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = unfolded.last_mut() {
                last.push_str(&line[1..]);
                continue;
            }
        }
        unfolded.push(line.to_string());
    }
    unfolded
}

pub fn parse_manifest_entrypoints(manifest: &str, declared: &mut Vec<String>) {
    for line in unfold_manifest_lines(manifest) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();

        if let Some(rest) = line.strip_prefix("Fabric-Loom-Client-Only-Entries:") {
            for token in rest.split(|c: char| c == ';' || c == ',' || c.is_whitespace()) {
                let t = token.trim();
                if let Some(stripped) = t.strip_suffix(".class") {
                    declared.push(stripped.to_string());
                }
            }
        } else if lower.starts_with("main-class:")
            || lower.starts_with("premain-class:")
            || lower.starts_with("agent-class:")
            || lower.starts_with("launcher-agent-class:")
        {
            if let Some((_, val)) = trimmed.split_once(':') {
                let val = val.trim();
                if !val.is_empty() {
                    let internal = val.replace('.', "/");
                    declared.push(internal);
                }
            }
        }
    }
}

pub fn parse_entrypoints(fabric_json: Option<&str>, manifest: Option<&str>) -> Vec<String> {
    let mut declared = Vec::new();
    if let Some(json_str) = fabric_json {
        parse_fabric_entrypoints(json_str, &mut declared);
    }
    if let Some(mf) = manifest {
        parse_manifest_entrypoints(mf, &mut declared);
    }
    declared
}

pub fn find_missing_entrypoints(
    declared: Vec<String>,
    entry_names: &HashSet<String>,
) -> Vec<String> {
    let mut missing: Vec<String> = declared
        .into_iter()
        .filter(|name| {
            let class_name = format!("{name}.class");
            !entry_names.contains(&class_name) && !entry_names.contains(name)
        })
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fabric_entrypoint_value_normalizes_dot_to_slash_and_strips_method() {
        assert_eq!(
            parse_fabric_entrypoint_value("net.example.ModClient"),
            Some("net/example/ModClient".to_string())
        );
        assert_eq!(
            parse_fabric_entrypoint_value("net.example.ModClient::init"),
            Some("net/example/ModClient".to_string())
        );
        assert_eq!(parse_fabric_entrypoint_value(""), None);
    }

    #[test]
    fn parse_fabric_entrypoints_with_bom() {
        let json_with_bom = "\u{FEFF}{\"entrypoints\": {\"main\": [\"net.example.Mod\"]}}";
        let mut declared = Vec::new();
        parse_fabric_entrypoints(json_with_bom, &mut declared);
        assert_eq!(declared, vec!["net/example/Mod".to_string()]);
    }

    #[test]
    fn unfold_manifest_lines_joins_continuation_lines() {
        let mf = "Header: Value\r\n ContinuationLine\r\nOther: Normal";
        let unfolded = unfold_manifest_lines(mf);
        assert_eq!(unfolded.len(), 2);
        assert_eq!(unfolded[0], "Header: ValueContinuationLine");
        assert_eq!(unfolded[1], "Other: Normal");
    }

    #[test]
    fn parse_manifest_entrypoints_supports_main_class() {
        let mf = "Main-Class: com.example.MyMain\r\nPremain-Class: com.example.Agent";
        let mut declared = Vec::new();
        parse_manifest_entrypoints(mf, &mut declared);
        assert!(declared.contains(&"com/example/MyMain".to_string()));
        assert!(declared.contains(&"com/example/Agent".to_string()));
    }
}
