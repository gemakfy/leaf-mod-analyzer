use std::collections::{HashMap, HashSet};

/// JVM class file magic number (0xCAFEBABE).
pub const JVM_MAGIC: &[u8; 4] = b"\xCA\xFE\xBA\xBE";

// Constant pool tags (JVM Spec §4.4)
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

// Selected JVM opcodes (JVM Spec §6.5)
const OP_TABLESWITCH: u8 = 0xAA;
const OP_LOOKUPSWITCH: u8 = 0xAB;
const OP_INVOKEVIRTUAL: u8 = 0xB6;
const OP_INVOKEINTERFACE: u8 = 0xB9;
const OP_WIDE: u8 = 0xC4;

/// Safe, zero-allocation byte reader over borrowed binary data.
#[derive(Clone, Copy)]
pub struct ByteReader<'a> {
    data: &'a [u8],
}

impl<'a> ByteReader<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline]
    pub fn read_u8(&mut self) -> Option<u8> {
        let (&first, rest) = self.data.split_first()?;
        self.data = rest;
        Some(first)
    }

    #[inline]
    pub fn read_u16(&mut self) -> Option<u16> {
        if self.data.len() < 2 {
            return None;
        }
        let (bytes, rest) = self.data.split_at(2);
        self.data = rest;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    pub fn read_u32(&mut self) -> Option<u32> {
        if self.data.len() < 4 {
            return None;
        }
        let (bytes, rest) = self.data.split_at(4);
        self.data = rest;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.data.len() < len {
            return None;
        }
        let (bytes, rest) = self.data.split_at(len);
        self.data = rest;
        Some(bytes)
    }

    #[inline]
    pub fn skip(&mut self, len: usize) -> Option<()> {
        if self.data.len() < len {
            return None;
        }
        self.data = &self.data[len..];
        Some(())
    }

    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }
}

// Backward-compatible slice helper functions
#[inline]
pub fn read_u1(cursor: &mut &[u8]) -> Option<u8> {
    ByteReader::new(cursor).read_u8().inspect(|_| *cursor = &cursor[1..])
}

#[inline]
pub fn read_u2(cursor: &mut &[u8]) -> Option<u16> {
    ByteReader::new(cursor).read_u16().inspect(|_| *cursor = &cursor[2..])
}

#[inline]
pub fn read_u4(cursor: &mut &[u8]) -> Option<u32> {
    ByteReader::new(cursor).read_u32().inspect(|_| *cursor = &cursor[4..])
}

/// Decode standard and JVM Modified UTF-8 strings.
pub fn decode_modified_utf8(bytes: &[u8]) -> String {
    // Fast path: standard UTF-8 without embedded NUL
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
    #[inline]
    pub fn get_utf8(&self, idx: u16) -> Option<&str> {
        self.utf8.get(&idx).map(|s| s.as_str())
    }

    #[inline]
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

pub fn parse_constant_pool(reader: &mut ByteReader) -> Option<ConstantPool> {
    let count = reader.read_u16()? as usize;
    if count == 0 {
        return None;
    }

    let mut cp = ConstantPool::default();
    let mut idx = 1;
    while idx < count {
        let tag = reader.read_u8()?;
        match tag {
            CONSTANT_UTF8 => {
                let len = reader.read_u16()? as usize;
                let bytes = reader.read_bytes(len)?;
                cp.utf8.insert(idx as u16, decode_modified_utf8(bytes));
            }
            CONSTANT_INTEGER => {
                reader.skip(4)?;
            }
            CONSTANT_FLOAT => {
                let bits = reader.read_u32()?;
                cp.float_constants.push(f32::from_bits(bits) as f64);
            }
            CONSTANT_DOUBLE => {
                let bytes = reader.read_bytes(8)?;
                let bits = u64::from_be_bytes(bytes.try_into().ok()?);
                cp.float_constants.push(f64::from_bits(bits));
                idx += 1; // 8-byte constants take two pool entries
            }
            CONSTANT_LONG => {
                reader.skip(8)?;
                idx += 1;
            }
            CONSTANT_CLASS => {
                cp.classes.insert(idx as u16, reader.read_u16()?);
            }
            CONSTANT_STRING => {
                cp.strings.insert(idx as u16, reader.read_u16()?);
            }
            CONSTANT_FIELDREF => {
                let class_idx = reader.read_u16()?;
                let nt_idx = reader.read_u16()?;
                cp.field_refs.insert(idx as u16, (class_idx, nt_idx));
            }
            CONSTANT_METHODREF | CONSTANT_INTERFACE_METHODREF => {
                let class_idx = reader.read_u16()?;
                let nt_idx = reader.read_u16()?;
                cp.method_refs.insert(idx as u16, (class_idx, nt_idx));
            }
            CONSTANT_NAME_AND_TYPE => {
                let name_idx = reader.read_u16()?;
                let desc_idx = reader.read_u16()?;
                cp.name_and_types.insert(idx as u16, (name_idx, desc_idx));
            }
            CONSTANT_METHOD_HANDLE => {
                reader.skip(3)?;
            }
            CONSTANT_METHOD_TYPE => {
                reader.skip(2)?;
            }
            CONSTANT_DYNAMIC | CONSTANT_INVOKE_DYNAMIC => {
                reader.skip(4)?;
            }
            CONSTANT_MODULE | CONSTANT_PACKAGE => {
                reader.skip(2)?;
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

/// Check if an identifier consists of visually confusable homoglyphs (e.g. IlIl, O0O).
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
    if raw.len() < 10 || &raw[0..4] != JVM_MAGIC {
        return None;
    }

    let mut reader = ByteReader::new(&raw[8..]); // skip magic and version
    let cp = parse_constant_pool(&mut reader)?;

    let _access_flags = reader.read_u16()?;
    let this_class_idx = reader.read_u16()?;
    let _super_class_idx = reader.read_u16()?;

    let this_class = cp.get_class_name(this_class_idx)?.to_string();
    let simple_name = this_class.rsplit('/').next().unwrap_or(&this_class).to_string();

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
}

fn parse_fields(
    reader: &mut ByteReader,
    cp: &ConstantPool,
    data: &mut RawClassData,
) -> Option<()> {
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

fn parse_attributes(
    reader: &mut ByteReader,
    cp: &ConstantPool,
    data: &mut RawClassData,
    method_sig: Option<&str>,
) -> Option<()> {
    let attr_count = reader.read_u16()? as usize;
    for _ in 0..attr_count {
        let name_idx = reader.read_u16()?;
        let length = reader.read_u32()? as usize;
        let attr_data = reader.read_bytes(length)?;

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
    code_attr: &[u8],
    cp: &ConstantPool,
    data: &mut RawClassData,
    method_sig: Option<&str>,
) -> Option<()> {
    let mut reader = ByteReader::new(code_attr);
    let _max_stack = reader.read_u16()?;
    let _max_locals = reader.read_u16()?;
    let code_len = reader.read_u32()? as usize;
    let bytecode = reader.read_bytes(code_len)?;

    let mut offset = 0;
    let mut has_switch = false;
    let mut m_refs: HashSet<String> = HashSet::new();

    while offset < bytecode.len() {
        let op = bytecode[offset];
        if (OP_INVOKEVIRTUAL..=OP_INVOKEINTERFACE).contains(&op) && offset + 2 < bytecode.len() {
            let cp_idx = u16::from_be_bytes([bytecode[offset + 1], bytecode[offset + 2]]);
            if let Some((owner, name, desc)) = cp.resolve_member_ref(cp_idx, true) {
                m_refs.insert(format!("{owner}.{name}"));
                if owner == "java/lang/StringBuilder" && name == "append" && desc == "(C)Ljava/lang/StringBuilder;" {
                    data.char_append_count += 1;
                }
            }
        } else if op == OP_TABLESWITCH || op == OP_LOOKUPSWITCH {
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
    if op == OP_TABLESWITCH {
        let mut i = offset + 1;
        while !i.is_multiple_of(4) {
            i += 1;
        }
        if i + 12 > code.len() {
            return code.len();
        }
        let low = i32::from_be_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]);
        let high = i32::from_be_bytes([code[i + 8], code[i + 9], code[i + 10], code[i + 11]]);
        let count = (high - low + 1).max(0) as usize;
        return i + 12 + 4 * count;
    }
    if op == OP_LOOKUPSWITCH {
        let mut i = offset + 1;
        while !i.is_multiple_of(4) {
            i += 1;
        }
        if i + 8 > code.len() {
            return code.len();
        }
        let npairs = i32::from_be_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]).max(0) as usize;
        return i + 8 + 8 * npairs;
    }
    if op == OP_WIDE {
        if offset + 1 >= code.len() {
            return code.len();
        }
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
    attr_data: &[u8],
    cp: &ConstantPool,
    out: &mut Vec<(String, HashMap<String, Vec<String>>)>,
) -> Option<()> {
    let mut reader = ByteReader::new(attr_data);
    let count = reader.read_u16()? as usize;
    for _ in 0..count {
        if let Some(ann) = parse_one_annotation(&mut reader, cp) {
            out.push(ann);
        }
    }
    Some(())
}

fn parse_one_annotation(
    reader: &mut ByteReader,
    cp: &ConstantPool,
) -> Option<(String, HashMap<String, Vec<String>>)> {
    let type_idx = reader.read_u16()?;
    let type_name = cp.get_utf8(type_idx)?.to_string();
    let num_pairs = reader.read_u16()? as usize;
    let mut elements: HashMap<String, Vec<String>> = HashMap::new();

    for _ in 0..num_pairs {
        let name_idx = reader.read_u16()?;
        let name = cp.get_utf8(name_idx).unwrap_or("").to_string();
        let mut vals = Vec::new();
        read_element_value(reader, cp, &mut vals);
        if !name.is_empty() && !vals.is_empty() {
            elements.insert(name, vals);
        }
    }
    Some((type_name, elements))
}

fn read_element_value(reader: &mut ByteReader, cp: &ConstantPool, out: &mut Vec<String>) -> Option<()> {
    let tag = reader.read_u8()?;
    match tag {
        b's' | b'c' => {
            let idx = reader.read_u16()?;
            if let Some(s) = cp.get_utf8(idx) {
                out.push(s.to_string());
            }
        }
        b'e' => {
            let _enum_type_idx = reader.read_u16()?;
            let const_name_idx = reader.read_u16()?;
            if let Some(s) = cp.get_utf8(const_name_idx) {
                out.push(s.to_string());
            }
        }
        b'[' => {
            let num = reader.read_u16()? as usize;
            for _ in 0..num {
                read_element_value(reader, cp, out);
            }
        }
        b'@' => {
            let _type_idx = reader.read_u16()?;
            let pairs = reader.read_u16()? as usize;
            for _ in 0..pairs {
                let _name_idx = reader.read_u16()?;
                read_element_value(reader, cp, out);
            }
        }
        _ => {
            // Primitive tags have a 2-byte const_value_index
            let _ = reader.read_u16()?;
        }
    }
    Some(())
}
