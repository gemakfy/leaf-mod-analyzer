/// Safe, zero-allocation byte reader over borrowed binary data.
#[derive(Clone, Copy, Debug)]
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

/// Decode standard and JVM Modified UTF-8 strings, preserving surrogate pairs (e.g. emojis).
pub fn decode_modified_utf8(bytes: &[u8]) -> String {
    // Fast path: standard UTF-8 without embedded NUL
    if let Ok(s) = std::str::from_utf8(bytes) {
        if !s.contains('\0') {
            return s.to_string();
        }
    }

    let mut u16_buf: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            u16_buf.push(b as u16);
            i += 1;
        } else if b & 0xE0 == 0xC0 && i + 1 < bytes.len() {
            let b2 = bytes[i + 1];
            if b == 0xC0 && b2 == 0x80 {
                u16_buf.push(0x0000);
            } else {
                let code_unit = (((b & 0x1F) as u16) << 6) | ((b2 & 0x3F) as u16);
                u16_buf.push(code_unit);
            }
            i += 2;
        } else if b & 0xF0 == 0xE0 && i + 2 < bytes.len() {
            let b2 = bytes[i + 1];
            let b3 = bytes[i + 2];
            let code_unit = (((b & 0x0F) as u16) << 12) | (((b2 & 0x3F) as u16) << 6) | ((b3 & 0x3F) as u16);
            u16_buf.push(code_unit);
            i += 3;
        } else {
            // Invalid byte, represent as replacement character
            u16_buf.push(0xFFFD);
            i += 1;
        }
    }
    String::from_utf16_lossy(&u16_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_should_read_integers_correctly() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
        let mut reader = ByteReader::new(&data);

        assert_eq!(reader.len(), 7);
        assert!(!reader.is_empty());
        assert_eq!(reader.read_u8(), Some(0x12));
        assert_eq!(reader.read_u16(), Some(0x3456));
        assert_eq!(reader.read_u32(), Some(0x789ABCDE));
        assert_eq!(reader.read_u8(), None);
        assert!(reader.is_empty());
    }

    #[test]
    fn reader_should_return_none_on_insufficient_bytes() {
        let data = [0x01, 0x02];
        let mut reader = ByteReader::new(&data);
        assert_eq!(reader.read_u32(), None);
        assert_eq!(reader.len(), 2);
    }

    #[test]
    fn decode_modified_utf8_handles_ascii_and_null() {
        let ascii = b"Hello, World!";
        assert_eq!(decode_modified_utf8(ascii), "Hello, World!");

        let jvm_null = [0xC0, 0x80];
        assert_eq!(decode_modified_utf8(&jvm_null), "\0");
    }

    #[test]
    fn decode_modified_utf8_handles_surrogate_pairs_emojis() {
        // U+1F600 (Grinning Face): high surrogate 0xD83D, low surrogate 0xDE00
        // in Modified UTF-8: ED A0 BD (D83D) and ED B8 80 (DE00)
        let emoji_m_utf8 = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_modified_utf8(&emoji_m_utf8), "😀");
    }
}
