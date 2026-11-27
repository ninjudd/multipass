//! SHA-1 (FIPS 180-4 § 6.1). multipass uses it only inside HMAC, for the
//! one-time passwords that RFC 6238 and most sites define with it; HMAC-SHA-1
//! does not depend on the collision resistance that SHA-1 has lost.

use super::hmac::{BlockBuffer, Digest};

const INITIAL: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

pub struct Sha1 {
    state: [u32; 5],
    blocks: BlockBuffer<64>,
}

impl Digest for Sha1 {
    const BLOCK_LEN: usize = 64;
    type Output = [u8; 20];

    fn new() -> Self {
        Self {
            state: INITIAL,
            blocks: BlockBuffer::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.blocks
            .update(data, |block| compress(&mut self.state, block));
    }

    fn finalize(mut self) -> [u8; 20] {
        let state = &mut self.state;
        self.blocks.finish(8, |block| compress(state, block));
        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, word) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, w) in w.iter().enumerate() {
        let (f, k) = match i / 20 {
            0 => ((b & c) | (!b & d), 0x5a827999),
            1 => (b ^ c ^ d, 0x6ed9eba1),
            2 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*w);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn matches_fips_180_and_rfc_3174_vectors() {
        let cases: [(&[u8], &str); 3] = [
            (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(Sha1::digest(input).to_vec(), hex(expected));
        }
    }

    #[test]
    fn handles_a_million_bytes_fed_unevenly() {
        let mut hasher = Sha1::new();
        for piece in vec![b'a'; 1_000_000].chunks(997) {
            hasher.update(piece);
        }
        assert_eq!(
            hasher.finalize().to_vec(),
            hex("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
    }
}
