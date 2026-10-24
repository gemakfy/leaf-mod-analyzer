use std::collections::{HashMap, HashSet};

pub mod attributes;
pub mod constant_pool;
pub mod opcodes;
pub mod reader;

pub use attributes::parse_attributes;
pub use constant_pool::{parse_constant_pool, ConstantPool};
pub use opcodes::*;
pub use reader::{decode_modified_utf8, ByteReader};

/// JVM class file magic number (0xCAFEBABE).
pub const JVM_MAGIC: &[u8; 4] = b"\xCA\xFE\xBA\xBE";

#[derive(Default)]
pub struct RawClassData {
    pub this_class: String,
    pub simple_name: String,
    pub class_refs: HashSet<String>,
    pub field_refs: HashSet<String>,
    pub method_refs: HashSet<String>,
    pub strings: HashSet<String>,
    pub float_constants: Vec<f64>,
    pub member_names: HashSet<String>,
    pub annotations: Vec<(String, HashMap<String, Vec<String>>)>,
    pub char_append_count: usize,
    pub method_refs_by_method: HashMap<String, HashSet<String>>,
    pub total_methods: usize,
    pub switch_methods: usize,
    pub encrypted_string_count: usize,
}

/// Check if an identifier consists of visually confusable homoglyphs ([Il][Il1]+ | [O][O0]+)
/// or stealthy mixed-script characters (Latin + Cyrillic lookalikes).
pub fn is_homoglyph(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 2 {
        return false;
    }

    match bytes[0] {
        b'I' | b'l' if bytes[1..].iter().all(|&b| matches!(b, b'I' | b'l' | b'1')) => {
            return true;
        }
        b'O' if bytes[1..].iter().all(|&b| matches!(b, b'O' | b'0')) => {
            return true;
        }
        _ => {}
    }

    if name.is_ascii() {
        return false;
    }

    // Mixed script homoglyphs (e.g. disguising Latin 'player' with Cyrillic 'р')
    let mut has_latin = false;
    let mut has_cyrillic = false;
    for c in name.chars() {
        if c.is_ascii_alphabetic() {
            has_latin = true;
        } else if ('\u{0400}'..='\u{04FF}').contains(&c) {
            has_cyrillic = true;
        }
        if has_latin && has_cyrillic {
            return true;
        }
    }
    false
}

pub fn parse_class(raw: &[u8]) -> Option<RawClassData> {
    if raw.len() < 10 || &raw[0..4] != JVM_MAGIC {
        return None;
    }

    let mut reader = ByteReader::new(&raw[8..]); // skip magic and version
    let cp = parse_constant_pool(&mut reader)?;

    let _access_flags = reader.read_u16()?;
    let this_class_idx = reader.read_u16()?;
    let _super_class_idx = reader.read_u16()?;

    let this_class = cp.get_class_name(this_class_idx)?.to_string();
    let simple_name = this_class
        .rsplit('/')
        .next()
        .unwrap_or(&this_class)
        .to_string();

    let mut data = RawClassData {
        this_class,
        simple_name,
        ..Default::default()
    };

    populate_constant_pool_facts(&cp, &mut data);

    // Skip interfaces
    let interfaces_count = reader.read_u16()? as usize;
    reader.skip(interfaces_count * 2)?;

    parse_fields(&mut reader, &cp, &mut data)?;
    parse_methods(&mut reader, &cp, &mut data)?;
    parse_attributes(&mut reader, &cp, &mut data, None)?;

    Some(data)
}

fn populate_constant_pool_facts(cp: &ConstantPool, data: &mut RawClassData) {
    for &name_idx in cp.classes.values() {
        if let Some(s) = cp.get_utf8(name_idx) {
            data.class_refs.insert(s.to_string());
        }
    }
    for &str_idx in cp.strings.values() {
        if let Some(s) = cp.get_utf8(str_idx) {
            if crate::is_encrypted_string(s) {
                data.encrypted_string_count += 1;
            }
            data.strings.insert(s.to_string());
        }
    }
    for &idx in cp.field_refs.keys() {
        if let Some((owner, name, _)) = cp.resolve_member_ref(idx, false) {
            data.field_refs.insert(format!("{owner}.{name}"));
        }
    }
    for &idx in cp.method_refs.keys() {
        if let Some((owner, name, _)) = cp.resolve_member_ref(idx, true) {
            data.method_refs.insert(format!("{owner}.{name}"));
        }
    }
    data.float_constants = cp.float_constants.clone();
}

fn parse_fields(reader: &mut ByteReader, cp: &ConstantPool, data: &mut RawClassData) -> Option<()> {
    let fields_count = reader.read_u16()? as usize;
    for _ in 0..fields_count {
        let _f_access = reader.read_u16()?;
        let name_idx = reader.read_u16()?;
        let _desc_idx = reader.read_u16()?;
        if let Some(name) = cp.get_utf8(name_idx) {
            data.member_names.insert(name.to_string());
        }
        parse_attributes(reader, cp, data, None)?;
    }
    Some(())
}

fn parse_methods(
    reader: &mut ByteReader,
    cp: &ConstantPool,
    data: &mut RawClassData,
) -> Option<()> {
    let methods_count = reader.read_u16()? as usize;
    data.total_methods = methods_count;
    for _ in 0..methods_count {
        let _m_access = reader.read_u16()?;
        let name_idx = reader.read_u16()?;
        let desc_idx = reader.read_u16()?;
        let m_name = cp.get_utf8(name_idx).unwrap_or("").to_string();
        let m_desc = cp.get_utf8(desc_idx).unwrap_or("").to_string();
        if !m_name.is_empty() {
            data.member_names.insert(m_name.clone());
        }
        let m_sig = format!("{m_name}{m_desc}");
        parse_attributes(reader, cp, data, Some(&m_sig))?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_homoglyph_detects_visual_confusables() {
        assert!(is_homoglyph("IlIl"));
        assert!(is_homoglyph("l1l1"));
        assert!(is_homoglyph("O0O0"));
        assert!(is_homoglyph("Il"));
        assert!(is_homoglyph("ll"));
        assert!(!is_homoglyph("NormalName"));
    }

    #[test]
    fn is_homoglyph_detects_mixed_cyrillic() {
        // "plаyer" with Cyrillic 'а' (\u0430)
        assert!(is_homoglyph("pl\u{0430}yer"));
    }

    #[test]
    fn parse_class_rejects_invalid_magic() {
        let invalid = b"NOT_A_CLASS_FILE";
        assert!(parse_class(invalid).is_none());
    }
}
