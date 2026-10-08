use std::collections::{HashMap, HashSet};

const CONSTANT_UTF8: u8 = 1;
const CONSTANT_INTEGER: u8 = 3;
const CONSTANT_FLOAT: u8 = 4;
const CONSTANT_LONG: u8 = 5;
const CONSTANT_DOUBLE: u8 = 6;
const CONSTANT_CLASS: u8 = 7;
const CONSTANT_STRING: u8 = 8;
const CONSTANT_FIELDREF: u8 = 9;
const CONSTANT_METHODREF: u8 = 10;
const CONSTANT_INTERFACE_METHODREF: u8 = 11;
const CONSTANT_NAME_AND_TYPE: u8 = 12;
const CONSTANT_METHOD_HANDLE: u8 = 15;
const CONSTANT_METHOD_TYPE: u8 = 16;
const CONSTANT_DYNAMIC: u8 = 17;
const CONSTANT_INVOKE_DYNAMIC: u8 = 18;
const CONSTANT_MODULE: u8 = 19;
const CONSTANT_PACKAGE: u8 = 20;

#[inline]
pub fn read_u1(cursor: &mut &[u8]) -> Option<u8> {
    if cursor.is_empty() {
        return None;
    }
    let b = cursor[0];
    *cursor = &cursor[1..];
    Some(b)
}

#[inline]
pub fn read_u2(cursor: &mut &[u8]) -> Option<u16> {
    if cursor.len() < 2 {
        return None;
    }
    let val = u16::from_be_bytes([cursor[0], cursor[1]]);
    *cursor = &cursor[2..];
    Some(val)
}

#[inline]
pub fn read_u4(cursor: &mut &[u8]) -> Option<u32> {
    if cursor.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Some(val)
}

pub fn decode_modified_utf8(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if !s.contains('\0') {
            return s.to_string();
        }
    }
    let mut result = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            result.push(b as char);
            i += 1;
        } else if b & 0xE0 == 0xC0 && i + 1 < bytes.len() {
            let b2 = bytes[i + 1];
            if b == 0xC0 && b2 == 0x80 {
                result.push('\0');
            } else {
                let ch = (((b & 0x1F) as u32) << 6) | ((b2 & 0x3F) as u32);
                if let Some(c) = char::from_u32(ch) {
                    result.push(c);
                }
            }
            i += 2;
        } else if b & 0xF0 == 0xE0 && i + 2 < bytes.len() {
            let b2 = bytes[i + 1];
            let b3 = bytes[i + 2];
            let ch = (((b & 0x0F) as u32) << 12) | (((b2 & 0x3F) as u32) << 6) | ((b3 & 0x3F) as u32);
            if let Some(c) = char::from_u32(ch) {
                result.push(c);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    result
}

#[derive(Default)]
pub struct ConstantPool {
    pub utf8: HashMap<u16, String>,
    pub classes: HashMap<u16, u16>,
    pub strings: HashMap<u16, u16>,
    pub field_refs: HashMap<u16, (u16, u16)>,
    pub method_refs: HashMap<u16, (u16, u16)>,
    pub name_and_types: HashMap<u16, (u16, u16)>,
    pub float_constants: Vec<f64>,
}

impl ConstantPool {
    pub fn get_utf8(&self, idx: u16) -> Option<&str> {
        self.utf8.get(&idx).map(|s| s.as_str())
    }

    pub fn get_class_name(&self, idx: u16) -> Option<&str> {
        let name_idx = self.classes.get(&idx)?;
        self.get_utf8(*name_idx)
    }

    pub fn resolve_member_ref(&self, idx: u16, is_method: bool) -> Option<(String, String, String)> {
        let map = if is_method { &self.method_refs } else { &self.field_refs };
        let (class_idx, nt_idx) = map.get(&idx)?;
        let owner = self.get_class_name(*class_idx)?;
        let (name_idx, desc_idx) = self.name_and_types.get(nt_idx)?;
        let name = self.get_utf8(*name_idx)?;
        let desc = self.get_utf8(*desc_idx)?;
        Some((owner.to_string(), name.to_string(), desc.to_string()))
    }
}

pub fn parse_constant_pool(cursor: &mut &[u8]) -> Option<ConstantPool> {
    let count = read_u2(cursor)? as usize;
    if count == 0 {
        return None;
    }
    let mut cp = ConstantPool::default();
    let mut idx = 1;
    while idx < count {
        let tag = read_u1(cursor)?;
        match tag {
            CONSTANT_UTF8 => {
                let len = read_u2(cursor)? as usize;
                if cursor.len() < len {
                    return None;
                }
                let bytes = &cursor[..len];
                *cursor = &cursor[len..];
                cp.utf8.insert(idx as u16, decode_modified_utf8(bytes));
            }
            CONSTANT_INTEGER => {
                if cursor.len() < 4 { return None; }
                *cursor = &cursor[4..];
            }
            CONSTANT_FLOAT => {
                let bits = read_u4(cursor)?;
                cp.float_constants.push(f32::from_bits(bits) as f64);
            }
            CONSTANT_DOUBLE => {
                if cursor.len() < 8 { return None; }
                let bits = u64::from_be_bytes([
                    cursor[0], cursor[1], cursor[2], cursor[3],
                    cursor[4], cursor[5], cursor[6], cursor[7],
                ]);
                *cursor = &cursor[8..];
                cp.float_constants.push(f64::from_bits(bits));
                idx += 1;
            }
            CONSTANT_LONG => {
                if cursor.len() < 8 { return None; }
                *cursor = &cursor[8..];
                idx += 1;
            }
            CONSTANT_CLASS => {
                let name_idx = read_u2(cursor)?;
                cp.classes.insert(idx as u16, name_idx);
            }
            CONSTANT_STRING => {
                let str_idx = read_u2(cursor)?;
                cp.strings.insert(idx as u16, str_idx);
            }
            CONSTANT_FIELDREF => {
                let class_idx = read_u2(cursor)?;
                let nt_idx = read_u2(cursor)?;
                cp.field_refs.insert(idx as u16, (class_idx, nt_idx));
            }
            CONSTANT_METHODREF | CONSTANT_INTERFACE_METHODREF => {
                let class_idx = read_u2(cursor)?;
                let nt_idx = read_u2(cursor)?;
                cp.method_refs.insert(idx as u16, (class_idx, nt_idx));
            }
            CONSTANT_NAME_AND_TYPE => {
                let name_idx = read_u2(cursor)?;
                let desc_idx = read_u2(cursor)?;
                cp.name_and_types.insert(idx as u16, (name_idx, desc_idx));
            }
            CONSTANT_METHOD_HANDLE => {
                if cursor.len() < 3 { return None; }
                *cursor = &cursor[3..];
            }
            CONSTANT_METHOD_TYPE => {
                if cursor.len() < 2 { return None; }
                *cursor = &cursor[2..];
            }
            CONSTANT_DYNAMIC | CONSTANT_INVOKE_DYNAMIC => {
                if cursor.len() < 4 { return None; }
                *cursor = &cursor[4..];
            }
            CONSTANT_MODULE | CONSTANT_PACKAGE => {
                if cursor.len() < 2 { return None; }
                *cursor = &cursor[2..];
            }
            _ => return None,
        }
        idx += 1;
    }
    Some(cp)
}

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
    pub has_encrypted_strings: usize,
}

pub fn is_homoglyph(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    if bytes[0] == b'I' || bytes[0] == b'l' {
        bytes[1..].iter().all(|&b| b == b'I' || b == b'l' || b == b'1')
    } else if bytes[0] == b'O' {
        bytes[1..].iter().all(|&b| b == b'O' || b == b'0')
    } else {
        false
    }
}

pub fn parse_class(raw: &[u8]) -> Option<RawClassData> {
    if raw.len() < 10 || &raw[0..4] != b"\xCA\xFE\xBA\xBE" {
        return None;
    }
    let mut cursor = &raw[8..]; // skip magic and version
    let cp = parse_constant_pool(&mut cursor)?;

    let _access_flags = read_u2(&mut cursor)?;
    let this_class_idx = read_u2(&mut cursor)?;
    let _super_class_idx = read_u2(&mut cursor)?;

    let this_class = cp.get_class_name(this_class_idx)?.to_string();
    let simple_name = this_class.rsplit('/').next().unwrap_or(&this_class).to_string();

    let mut data = RawClassData {
        this_class,
        simple_name,
        ..Default::default()
    };

    // Populate constant pool facts
    for &name_idx in cp.classes.values() {
        if let Some(s) = cp.get_utf8(name_idx) {
            data.class_refs.insert(s.to_string());
        }
    }
    for &str_idx in cp.strings.values() {
        if let Some(s) = cp.get_utf8(str_idx) {
            if crate::is_encrypted_string(s) {
                data.has_encrypted_strings += 1;
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

    // Skip interfaces
    let interfaces_count = read_u2(&mut cursor)? as usize;
    if cursor.len() < interfaces_count * 2 {
        return None;
    }
    cursor = &cursor[interfaces_count * 2..];

    // Parse fields
    let fields_count = read_u2(&mut cursor)? as usize;
    for _ in 0..fields_count {
        let _f_access = read_u2(&mut cursor)?;
        let name_idx = read_u2(&mut cursor)?;
        let _desc_idx = read_u2(&mut cursor)?;
        if let Some(name) = cp.get_utf8(name_idx) {
            data.member_names.insert(name.to_string());
        }
        parse_attributes(&mut cursor, &cp, &mut data, None)?;
    }

    // Parse methods
    let methods_count = read_u2(&mut cursor)? as usize;
    data.total_methods = methods_count;
    for _ in 0..methods_count {
        let _m_access = read_u2(&mut cursor)?;
        let name_idx = read_u2(&mut cursor)?;
        let desc_idx = read_u2(&mut cursor)?;
        let m_name = cp.get_utf8(name_idx).unwrap_or("").to_string();
        let m_desc = cp.get_utf8(desc_idx).unwrap_or("").to_string();
        if !m_name.is_empty() {
            data.member_names.insert(m_name.clone());
        }
        let m_sig = format!("{m_name}{m_desc}");
        parse_attributes(&mut cursor, &cp, &mut data, Some(&m_sig))?;
    }

    // Parse class attributes (e.g. annotations)
    parse_attributes(&mut cursor, &cp, &mut data, None)?;

    Some(data)
}

fn parse_attributes(
    cursor: &mut &[u8],
    cp: &ConstantPool,
    data: &mut RawClassData,
    method_sig: Option<&str>,
) -> Option<()> {
    let attr_count = read_u2(cursor)? as usize;
    for _ in 0..attr_count {
        let name_idx = read_u2(cursor)?;
        let length = read_u4(cursor)? as usize;
        if cursor.len() < length {
            return None;
        }
        let attr_data = &cursor[..length];
        *cursor = &cursor[length..];

        let attr_name = cp.get_utf8(name_idx).unwrap_or("");
        if attr_name == "Code" {
            scan_code_attribute(attr_data, cp, data, method_sig);
        } else if attr_name == "RuntimeVisibleAnnotations" || attr_name == "RuntimeInvisibleAnnotations" {
            parse_annotation_attribute(attr_data, cp, &mut data.annotations);
        }
    }
    Some(())
}

fn scan_code_attribute(
    mut code_attr: &[u8],
    cp: &ConstantPool,
    data: &mut RawClassData,
    method_sig: Option<&str>,
) -> Option<()> {
    if code_attr.len() < 8 {
        return None;
    }
    let _max_stack = read_u2(&mut code_attr)?;
    let _max_locals = read_u2(&mut code_attr)?;
    let code_len = read_u4(&mut code_attr)? as usize;
    if code_attr.len() < code_len {
        return None;
    }
    let bytecode = &code_attr[..code_len];

    let mut offset = 0;
    let mut has_switch = false;
    let mut m_refs: HashSet<String> = HashSet::new();

    while offset < bytecode.len() {
        let op = bytecode[offset];
        if (0xB6..=0xB9).contains(&op) && offset + 2 < bytecode.len() {
            let cp_idx = u16::from_be_bytes([bytecode[offset + 1], bytecode[offset + 2]]);
            if let Some((owner, name, desc)) = cp.resolve_member_ref(cp_idx, true) {
                m_refs.insert(format!("{owner}.{name}"));
                if owner == "java/lang/StringBuilder" && name == "append" && desc == "(C)Ljava/lang/StringBuilder;" {
                    data.char_append_count += 1;
                }
            }
        } else if op == 0xAA || op == 0xAB {
            has_switch = true;
        }

        let next = next_pc(op, bytecode, offset);
        if next <= offset || next > bytecode.len() {
            break;
        }
        offset = next;
    }

    if has_switch {
        data.switch_methods += 1;
    }
    if let Some(sig) = method_sig {
        if !m_refs.is_empty() {
            data.method_refs_by_method.insert(sig.to_string(), m_refs);
        }
    }
    Some(())
}

fn next_pc(op: u8, code: &[u8], offset: usize) -> usize {
    if op == 0xAA { // tableswitch
        let mut i = offset + 1;
        while i % 4 != 0 { i += 1; }
        if i + 12 > code.len() { return code.len(); }
        let low = i32::from_be_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]);
        let high = i32::from_be_bytes([code[i + 8], code[i + 9], code[i + 10], code[i + 11]]);
        let count = (high - low + 1).max(0) as usize;
        return i + 12 + 4 * count;
    }
    if op == 0xAB { // lookupswitch
        let mut i = offset + 1;
        while i % 4 != 0 { i += 1; }
        if i + 8 > code.len() { return code.len(); }
        let npairs = i32::from_be_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]).max(0) as usize;
        return i + 8 + 8 * npairs;
    }
    if op == 0xC4 { // wide
        if offset + 1 >= code.len() { return code.len(); }
        return if code[offset + 1] == 0x84 { offset + 6 } else { offset + 4 };
    }

    let len = match op {
        0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3A | 0xBC => 2,
        0x11 | 0x13 | 0x14 | 0x99..=0xA8 | 0xB2..=0xB8 | 0xBB | 0xBD | 0xC0 | 0xC1 | 0xC6 | 0xC7 => 3,
        0xC5 => 4,
        0xB9 | 0xBA | 0xC8 | 0xC9 => 5,
        _ => 1,
    };
    offset + len
}

fn parse_annotation_attribute(
    mut cursor: &[u8],
    cp: &ConstantPool,
    out: &mut Vec<(String, HashMap<String, Vec<String>>)>,
) -> Option<()> {
    let count = read_u2(&mut cursor)? as usize;
    for _ in 0..count {
        if let Some(ann) = parse_one_annotation(&mut cursor, cp) {
            out.push(ann);
        }
    }
    Some(())
}

fn parse_one_annotation(
    cursor: &mut &[u8],
    cp: &ConstantPool,
) -> Option<(String, HashMap<String, Vec<String>>)> {
    let type_idx = read_u2(cursor)?;
    let type_name = cp.get_utf8(type_idx)?.to_string();
    let num_pairs = read_u2(cursor)? as usize;
    let mut elements: HashMap<String, Vec<String>> = HashMap::new();

    for _ in 0..num_pairs {
        let name_idx = read_u2(cursor)?;
        let name = cp.get_utf8(name_idx).unwrap_or("").to_string();
        let mut vals = Vec::new();
        read_element_value(cursor, cp, &mut vals);
        if !name.is_empty() && !vals.is_empty() {
            elements.insert(name, vals);
        }
    }
    Some((type_name, elements))
}

fn read_element_value(cursor: &mut &[u8], cp: &ConstantPool, out: &mut Vec<String>) -> Option<()> {
    let tag = read_u1(cursor)?;
    match tag {
        b's' => {
            let idx = read_u2(cursor)?;
            if let Some(s) = cp.get_utf8(idx) {
                out.push(s.to_string());
            }
        }
        b'c' => {
            let idx = read_u2(cursor)?;
            if let Some(s) = cp.get_utf8(idx) {
                out.push(s.to_string());
            }
        }
        b'e' => {
            let _t = read_u2(cursor)?;
            let v = read_u2(cursor)?;
            if let Some(s) = cp.get_utf8(v) {
                out.push(s.to_string());
            }
        }
        b'[' => {
            let num = read_u2(cursor)? as usize;
            for _ in 0..num {
                read_element_value(cursor, cp, out);
            }
        }
        b'@' => {
            let _t = read_u2(cursor)?;
            let pairs = read_u2(cursor)? as usize;
            for _ in 0..pairs {
                let _n = read_u2(cursor)?;
                read_element_value(cursor, cp, out);
            }
        }
        _ => {
            // Primitive tags have a 2-byte const_value_index
            let _ = read_u2(cursor)?;
        }
    }
    Some(())
}
