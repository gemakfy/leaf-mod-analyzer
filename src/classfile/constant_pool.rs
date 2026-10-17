use std::collections::HashMap;

use super::reader::{decode_modified_utf8, ByteReader};

// Constant pool tags (JVM Spec §4.4)
pub const CONSTANT_UTF8: u8 = 1;
pub const CONSTANT_INTEGER: u8 = 3;
pub const CONSTANT_FLOAT: u8 = 4;
pub const CONSTANT_LONG: u8 = 5;
pub const CONSTANT_DOUBLE: u8 = 6;
pub const CONSTANT_CLASS: u8 = 7;
pub const CONSTANT_STRING: u8 = 8;
pub const CONSTANT_FIELDREF: u8 = 9;
pub const CONSTANT_METHODREF: u8 = 10;
pub const CONSTANT_INTERFACE_METHODREF: u8 = 11;
pub const CONSTANT_NAME_AND_TYPE: u8 = 12;
pub const CONSTANT_METHOD_HANDLE: u8 = 15;
pub const CONSTANT_METHOD_TYPE: u8 = 16;
pub const CONSTANT_DYNAMIC: u8 = 17;
pub const CONSTANT_INVOKE_DYNAMIC: u8 = 18;
pub const CONSTANT_MODULE: u8 = 19;
pub const CONSTANT_PACKAGE: u8 = 20;

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

    pub fn resolve_member_ref(&self, idx: u16, is_method: bool) -> Option<(&str, &str, &str)> {
        let map = if is_method { &self.method_refs } else { &self.field_refs };
        let (class_idx, nt_idx) = map.get(&idx)?;
        let owner = self.get_class_name(*class_idx)?;
        let (name_idx, desc_idx) = self.name_and_types.get(nt_idx)?;
        let name = self.get_utf8(*name_idx)?;
        let desc = self.get_utf8(*desc_idx)?;
        Some((owner, name, desc))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_pool_should_return_none_when_empty() {
        let empty = [0x00, 0x00];
        let mut reader = ByteReader::new(&empty);
        assert!(parse_constant_pool(&mut reader).is_none());
    }

    #[test]
    fn constant_pool_should_parse_utf8_entry() {
        let mut data = vec![0x00, 0x02, CONSTANT_UTF8, 0x00, 0x04];
        data.extend_from_slice(b"test");

        let mut reader = ByteReader::new(&data);
        let cp = parse_constant_pool(&mut reader).expect("should parse CP");
        assert_eq!(cp.get_utf8(1), Some("test"));
    }
}
