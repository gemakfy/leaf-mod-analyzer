// Selected JVM opcodes (JVM Spec §6.5)
pub const OP_TABLESWITCH: u8 = 0xAA;
pub const OP_LOOKUPSWITCH: u8 = 0xAB;
pub const OP_INVOKEVIRTUAL: u8 = 0xB6;
pub const OP_INVOKEINTERFACE: u8 = 0xB9;
pub const OP_WIDE: u8 = 0xC4;

#[inline]
pub fn align_to_4_bytes(offset: usize) -> usize {
    (offset + 3) & !3
}

pub fn next_pc(op: u8, code: &[u8], offset: usize) -> usize {
    if op == OP_TABLESWITCH {
        let i = align_to_4_bytes(offset + 1);
        if i + 12 > code.len() {
            return code.len();
        }
        let low = i32::from_be_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]) as i64;
        let high =
            i32::from_be_bytes([code[i + 8], code[i + 9], code[i + 10], code[i + 11]]) as i64;
        let count = (high - low + 1).max(0) as usize;
        let Some(table_size) = count.checked_mul(4) else {
            return code.len();
        };
        return i.saturating_add(12).saturating_add(table_size);
    }
    if op == OP_LOOKUPSWITCH {
        let i = align_to_4_bytes(offset + 1);
        if i + 8 > code.len() {
            return code.len();
        }
        let npairs = i32::from_be_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]).max(0)
            as usize;
        let Some(pairs_size) = npairs.checked_mul(8) else {
            return code.len();
        };
        return i.saturating_add(8).saturating_add(pairs_size);
    }
    if op == OP_WIDE {
        if offset + 1 >= code.len() {
            return code.len();
        }
        return if code[offset + 1] == 0x84 {
            offset + 6
        } else {
            offset + 4
        };
    }

    let len = match op {
        // 2-byte opcodes (bipush, ldc, xload, xstore, ret, newarray)
        0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3A | 0xA9 | 0xBC => 2,
        // 3-byte opcodes (sipush, ldc_w, ldc2_w, iinc, branches, get/put, invokes, new, checkcast, etc.)
        0x11
        | 0x13
        | 0x14
        | 0x84
        | 0x99..=0xA8
        | 0xB2..=0xB8
        | 0xBB
        | 0xBD
        | 0xC0
        | 0xC1
        | 0xC6
        | 0xC7 => 3,
        // 4-byte opcodes (multianewarray)
        0xC5 => 4,
        // 5-byte opcodes (invokeinterface, invokedynamic, goto_w, jsr_w)
        0xB9 | 0xBA | 0xC8 | 0xC9 => 5,
        _ => 1,
    };
    offset + len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_to_4_bytes_should_compute_correct_offsets() {
        assert_eq!(align_to_4_bytes(0), 0);
        assert_eq!(align_to_4_bytes(1), 4);
        assert_eq!(align_to_4_bytes(2), 4);
        assert_eq!(align_to_4_bytes(3), 4);
        assert_eq!(align_to_4_bytes(4), 4);
        assert_eq!(align_to_4_bytes(5), 8);
    }

    #[test]
    fn next_pc_should_advance_fixed_opcodes() {
        let dummy = [0u8; 16];
        // nop (0x00) -> 1 byte
        assert_eq!(next_pc(0x00, &dummy, 0), 1);
        // bipush (0x10) -> 2 bytes
        assert_eq!(next_pc(0x10, &dummy, 0), 2);
        // ret (0xA9) -> 2 bytes
        assert_eq!(next_pc(0xA9, &dummy, 0), 2);
        // iinc (0x84) -> 3 bytes
        assert_eq!(next_pc(0x84, &dummy, 0), 3);
        // invokevirtual (0xB6) -> 3 bytes
        assert_eq!(next_pc(0xB6, &dummy, 0), 3);
        // invokeinterface (0xB9) -> 5 bytes
        assert_eq!(next_pc(0xB9, &dummy, 0), 5);
        // invokedynamic (0xBA) -> 5 bytes
        assert_eq!(next_pc(0xBA, &dummy, 0), 5);
    }

    #[test]
    fn tableswitch_handles_i32_overflow_safely() {
        // Construct tableswitch with low = i32::MIN, high = i32::MAX
        let mut code = vec![0xAA, 0x00, 0x00, 0x00]; // padding aligned
        code.extend_from_slice(&0i32.to_be_bytes()); // default
        code.extend_from_slice(&i32::MIN.to_be_bytes()); // low
        code.extend_from_slice(&i32::MAX.to_be_bytes()); // high
        let next = next_pc(OP_TABLESWITCH, &code, 0);
        // Should not panic on i32 subtraction overflow
        assert!(next >= code.len());
    }

    #[test]
    fn walk_does_not_desync_on_iinc_with_switch_lookalike() {
        // iinc 0, -86 (84 00 AA); return (B1)
        let code = [0x84, 0x00, 0xAA, 0xB1];
        let mut off = 0;
        let mut offsets = vec![];
        while off < code.len() {
            offsets.push(off);
            off = next_pc(code[off], &code, off);
        }
        assert_eq!(offsets, vec![0, 3]);
        assert_eq!(off, code.len());
    }
}
