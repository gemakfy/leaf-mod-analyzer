use std::collections::{HashMap, HashSet};

use super::constant_pool::ConstantPool;
use super::opcodes::{
    next_pc, OP_INVOKEINTERFACE, OP_INVOKEVIRTUAL, OP_LOOKUPSWITCH, OP_TABLESWITCH,
};
use super::reader::ByteReader;
use super::RawClassData;

const MAX_ANNOTATION_DEPTH: usize = 32;

pub fn parse_attributes(
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
        // Code attribute is only valid on methods (§4.7.3)
        if attr_name == "Code" && method_sig.is_some() {
            scan_code_attribute(attr_data, cp, data, method_sig);
        } else if attr_name == "RuntimeVisibleAnnotations"
            || attr_name == "RuntimeInvisibleAnnotations"
        {
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
                if owner == "java/lang/StringBuilder"
                    && name == "append"
                    && desc == "(C)Ljava/lang/StringBuilder;"
                {
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

fn parse_annotation_attribute(
    attr_data: &[u8],
    cp: &ConstantPool,
    out: &mut Vec<(String, HashMap<String, Vec<String>>)>,
) -> Option<()> {
    let mut reader = ByteReader::new(attr_data);
    let count = reader.read_u16()? as usize;
    for _ in 0..count {
        let ann = parse_one_annotation(&mut reader, cp)?;
        out.push(ann);
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
        read_element_value(reader, cp, &mut vals, 0)?;
        if !name.is_empty() && !vals.is_empty() {
            elements.insert(name, vals);
        }
    }
    Some((type_name, elements))
}

fn read_element_value(
    reader: &mut ByteReader,
    cp: &ConstantPool,
    out: &mut Vec<String>,
    depth: usize,
) -> Option<()> {
    if depth >= MAX_ANNOTATION_DEPTH {
        return None;
    }
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
                read_element_value(reader, cp, out, depth + 1)?;
            }
        }
        b'@' => {
            let _type_idx = reader.read_u16()?;
            let pairs = reader.read_u16()? as usize;
            for _ in 0..pairs {
                let _name_idx = reader.read_u16()?;
                read_element_value(reader, cp, out, depth + 1)?;
            }
        }
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' => {
            // Primitive tags have a 2-byte const_value_index
            let _ = reader.read_u16()?;
        }
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_nested_array_aborts_at_max_depth() {
        // Build nested array brackets b'[' > 32 levels deep
        let mut nested = Vec::new();
        for _ in 0..40 {
            nested.push(b'[');
            nested.extend_from_slice(&1u16.to_be_bytes()); // array of 1 element
        }
        nested.push(b's');
        nested.extend_from_slice(&1u16.to_be_bytes());

        let mut reader = ByteReader::new(&nested);
        let cp = ConstantPool::default();
        let mut out = Vec::new();
        let res = read_element_value(&mut reader, &cp, &mut out, 0);
        assert!(res.is_none());
    }
}
