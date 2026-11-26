//! Every cryptographic primitive multipass uses, written by hand so the
//! program has no dependencies. Each module is checked against the official
//! test vectors from its specification, and `crate::age` is checked against
//! files written by the reference age implementation.
//!
//! None of this code branches on secret data, but it has not been audited.

pub mod base64;
pub mod chacha20poly1305;
pub mod random;
pub mod scrypt;
pub mod sha256;

/// Compares two byte strings in time that depends only on their length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_compares_bytes() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
