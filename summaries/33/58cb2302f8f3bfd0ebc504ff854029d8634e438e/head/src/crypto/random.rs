//! Random bytes from the operating system's generator.

use std::fs::File;
use std::io::{self, Read};

/// Fills `buf` from `/dev/urandom`, which on macOS and Linux is the kernel's
/// cryptographic generator and never blocks once the system has booted.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buf)
}

/// 16 random bytes as 32 lower-case hex digits: a name for a key's
/// generation or a store file, which says nothing about any key. Ids are
/// public, so the hex table lookup leaks nothing.
pub fn id() -> io::Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 16];
    fill(&mut bytes)?;
    Ok(bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]])
        .map(char::from)
        .collect())
}

/// A new vault key: 32 random bytes as 43 characters of unpadded base64.
/// The text is the key; multipass passes it to age as a passphrase and
/// never decodes it.
pub fn key_text() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    fill(&mut bytes)?;
    Ok(super::base64::encode(&bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn produces_different_bytes_each_time() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::fill(&mut a).unwrap();
        super::fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn makes_ids_and_keys_of_the_right_shape() {
        let id = super::id().unwrap();
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_ne!(id, super::id().unwrap());
        let key = super::key_text().unwrap();
        assert_eq!(key.len(), 43);
        assert_eq!(crate::crypto::base64::decode(&key).unwrap().len(), 32);
    }
}
