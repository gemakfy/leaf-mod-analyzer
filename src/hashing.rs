use sha2::{Digest, Sha512};
use std::fs::File;
use std::io::{BufReader, Read};

const BUFFER_CAPACITY: usize = 512 * 1024;
const READ_CHUNK_SIZE: usize = 256 * 1024;

#[inline]
fn to_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX_CHARS[(b >> 4) as usize] as char);
        hex.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    hex
}

/// Computes SHA-512 hex digest of a file at the given path.
pub fn sha512_file(file_path: &str) -> std::io::Result<String> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::with_capacity(BUFFER_CAPACITY, file);
    let mut hasher = Sha512::new();
    let mut buffer = [0u8; READ_CHUNK_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(to_hex(&hasher.finalize()))
}

/// Computes SHA-512 hex digest of an in-memory byte slice.
pub fn sha512_bytes(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    to_hex(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha512_bytes_empty_string_matches_known_digest() {
        let digest = sha512_bytes(b"");
        assert_eq!(
            digest,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_file_computes_correct_digest() {
        let dir = std::env::temp_dir();
        let file_path = dir.join("mod_analyzer_sha512_test.bin");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"Hello, Minecraft Mod Analyzer!").unwrap();
        }

        let file_digest = sha512_file(file_path.to_str().unwrap()).unwrap();
        let mem_digest = sha512_bytes(b"Hello, Minecraft Mod Analyzer!");
        assert_eq!(file_digest, mem_digest);

        let _ = std::fs::remove_file(file_path);
    }
}
