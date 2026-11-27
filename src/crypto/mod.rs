//! Every cryptographic primitive multipass uses, written by hand so the
//! program has no dependencies. Each module is checked against the official
//! test vectors from its specification, and `crate::age` is checked against
//! files written by the reference age implementation.
//!
//! None of this code branches on secret data, but it has not been audited.

pub mod base32;
pub mod base64;
pub mod chacha20poly1305;
pub mod hmac;
pub mod hotp;
pub mod random;
pub mod scrypt;
pub mod sha1;
pub mod sha256;
pub mod sha512;

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

/// All ones when `a == b`, and zero otherwise, without branching.
pub fn ct_eq_mask(a: usize, b: usize) -> usize {
    let diff = a ^ b;
    ((diff | diff.wrapping_neg()) >> (usize::BITS - 1)).wrapping_sub(1)
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

    #[test]
    fn ct_eq_mask_is_all_ones_only_for_equal_values() {
        for (a, b) in [(0, 0), (7, 7), (usize::MAX, usize::MAX)] {
            assert_eq!(ct_eq_mask(a, b), usize::MAX);
        }
        for (a, b) in [(0, 1), (1, 0), (0, usize::MAX), (1 << 63, 0)] {
            assert_eq!(ct_eq_mask(a, b), 0);
        }
    }
}
