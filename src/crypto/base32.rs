//! Base32 (RFC 4648 § 6), for one-time password setup keys.
//!
//! A setup key is secret, so neither direction branches on a character or
//! indexes memory with one. Each character's value and class come from
//! masked arithmetic, and the decoder writes every output byte through a
//! masked pass over all output positions, because where a byte lands depends
//! on how many spaces came before it. The only thing either function reveals
//! is the key's length.

use super::ct_eq_mask;

/// 0xff when `lo <= c <= hi`, and 0 otherwise.
fn in_range(c: u8, lo: u8, hi: u8) -> u8 {
    let c = c as i16;
    (((lo as i16 - 1 - c) & (c - hi as i16 - 1)) >> 15) as u8
}

/// Decodes `s`, ignoring case, spaces, and `=` padding. Returns `None` when
/// `s` holds any other character. Trailing bits that do not fill a byte are
/// dropped, as authenticator apps do.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = vec![0u8; s.len() * 5 / 8];
    let mut written = 0usize;
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut invalid = 0u8;

    for &raw in s.as_bytes() {
        let c = raw.wrapping_sub(32 & in_range(raw, b'a', b'z'));
        let letter = in_range(c, b'A', b'Z');
        let digit = in_range(c, b'2', b'7');
        let skip = in_range(c, b' ', b' ') | in_range(c, b'=', b'=');
        let symbol = letter | digit;
        invalid |= !(symbol | skip);
        let value = (letter & c.wrapping_sub(b'A')) | (digit & c.wrapping_sub(b'2' - 26));

        let take = symbol as u32 * 0x0101_0101;
        acc = (acc & !take) | (((acc << 5) | value as u32) & take);
        bits += 5 & take;

        let emit = (7u32.wrapping_sub(bits) as i32 >> 31) as u32;
        let byte = (acc >> (bits.wrapping_sub(8) & 31)) as u8 & emit as u8;
        for (i, slot) in out.iter_mut().enumerate() {
            let hit = ct_eq_mask(i, written) as u8 & emit as u8;
            *slot = (*slot & !hit) | (byte & hit);
        }
        written += 1 & emit as usize;
        bits -= 8 & emit;
        acc &= (1 << bits) - 1;
    }

    if invalid != 0 {
        return None;
    }
    out.truncate(written);
    Some(out)
}

/// Encodes `data` in upper case without padding.
pub fn encode(data: &[u8]) -> String {
    let symbol = |v: u32| {
        let digit = ((25u32.wrapping_sub(v) as i32) >> 31) as u8;
        let v = v as u8;
        (b'A'.wrapping_add(v) & !digit) | (b'2'.wrapping_add(v).wrapping_sub(26) & digit)
    };
    let mut out = Vec::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol((acc >> bits) & 31));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(symbol((acc << (5 - bits)) & 31));
    }
    String::from_utf8(out).expect("base32 symbols are ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_4648_VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "MY======"),
        ("fo", "MZXQ===="),
        ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI======"),
    ];

    #[test]
    fn decodes_and_encodes_the_rfc_4648_vectors() {
        for (plain, encoded) in RFC_4648_VECTORS {
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes(), "{encoded}");
            assert_eq!(encode(plain.as_bytes()), encoded.trim_end_matches('='));
        }
    }

    #[test]
    fn reads_keys_as_sites_show_them() {
        let key = b"Hello!\xde\xad\xbe\xef".to_vec();
        for shown in [
            "JBSWY3DPEHPK3PXP",
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "jbsw y3dp ehpk 3pxp",
            " JBSWY3DPEHPK3PXP ",
        ] {
            assert_eq!(decode(shown).unwrap(), key, "{shown:?}");
        }
    }

    #[test]
    fn places_each_byte_correctly_after_a_space_anywhere() {
        let encoded = "MZXW6YTBOI";
        for i in 0..=encoded.len() {
            let spaced = format!("{} {}", &encoded[..i], &encoded[i..]);
            assert_eq!(decode(&spaced).unwrap(), b"foobar", "{spaced:?}");
        }
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        for bad in ["MZXW0", "MZXW1", "MZXW8", "MZ-XW", "MZXW6\n", "MZXWé"] {
            assert!(decode(bad).is_none(), "{bad:?} decoded");
        }
    }

    #[test]
    fn round_trips_every_byte() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }
}
