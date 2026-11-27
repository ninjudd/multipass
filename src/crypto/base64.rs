//! Standard base64 without padding (RFC 4648), as age writes it. Decoding is
//! strict: no padding, no other characters, and no stray bits in the last
//! character, so every value has exactly one encoding.

#[cfg(test)]
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data` without reading memory at an address that depends on it,
/// because it encodes the vault key: each 6-bit value becomes its character
/// by masked arithmetic rather than by indexing an alphabet. It branches only
/// on the length of `data`, which is public.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(char::from(character((n >> (18 - 6 * i)) & 63)));
        }
    }
    out
}

/// All ones when `v >= k`, and zero otherwise, for `v` below 64 and `k`
/// from 1 to 64.
fn at_least(v: u32, k: u32) -> u32 {
    0u32.wrapping_sub((k - 1).wrapping_sub(v) >> 31)
}

/// The character for the 6-bit value `v`: `A` to `Z`, `a` to `z`, `0` to
/// `9`, `+`, then `/`. Each step moves every value at or above the start of
/// a range from where the previous step left it to where that range begins.
fn character(v: u32) -> u8 {
    let mut c = v + u32::from(b'A');
    c = c.wrapping_add(at_least(v, 26) & 6);
    c = c.wrapping_sub(at_least(v, 52) & 75);
    c = c.wrapping_sub(at_least(v, 62) & 15);
    c = c.wrapping_add(at_least(v, 63) & 3);
    c as u8
}

fn value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(v as u32)
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        if n & ((1u32 << (24 - 8 * produced)) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..1 + produced]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_4648_without_padding() {
        let cases = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn maps_every_six_bit_value_as_the_alphabet_does() {
        for v in 0..64 {
            assert_eq!(character(v), ALPHABET[v as usize], "value {v}");
        }
    }

    #[test]
    fn round_trips_every_byte() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn rejects_non_canonical_input() {
        for bad in ["Zg==", "Zh", "Zm9", "Z", "Zm9v\n", "Zm-v", "Zm9vY"] {
            assert!(decode(bad).is_none(), "{bad:?} decoded");
        }
    }
}
