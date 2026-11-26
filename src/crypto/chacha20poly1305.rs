//! ChaCha20, Poly1305 and their AEAD construction (RFC 8439), with no
//! additional data, which is all age needs.

use super::ct_eq;

pub const TAG_LEN: usize = 16;

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn le32(bytes: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for i in 0..8 {
        state[4 + i] = le32(key, 4 * i);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = le32(nonce, 4 * i);
    }

    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&working[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let keystream = chacha20_block(key, counter.wrapping_add(i as u32), nonce);
        for (byte, k) in chunk.iter_mut().zip(keystream) {
            *byte ^= k;
        }
    }
}

/// Poly1305 with 26-bit limbs, after poly1305-donna.
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    const MASK: u32 = 0x3ff_ffff;
    let r0 = le32(key, 0) & 0x3ff_ffff;
    let r1 = (le32(key, 3) >> 2) & 0x3ff_ff03;
    let r2 = (le32(key, 6) >> 4) & 0x3ff_c0ff;
    let r3 = (le32(key, 9) >> 6) & 0x3f0_3fff;
    let r4 = (le32(key, 12) >> 8) & 0x00f_ffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);
    for chunk in msg.chunks(16) {
        // Each block is read as a little-endian number with a 1 appended,
        // so a full block gets 2^128 and a short block a 1 just past its end.
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;

        h0 += le32(&block, 0) & MASK;
        h1 += (le32(&block, 3) >> 2) & MASK;
        h2 += (le32(&block, 6) >> 4) & MASK;
        h3 += (le32(&block, 9) >> 6) & MASK;
        h4 += (le32(&block, 12) >> 8) | ((block[16] as u32) << 24);

        let m = |a: u32, b: u32| a as u64 * b as u64;
        let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
        let mut d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
        let mut d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
        let mut d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
        let mut d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);

        h0 = d0 as u32 & MASK;
        d1 += d0 >> 26;
        h1 = d1 as u32 & MASK;
        d2 += d1 >> 26;
        h2 = d2 as u32 & MASK;
        d3 += d2 >> 26;
        h3 = d3 as u32 & MASK;
        d4 += d3 >> 26;
        h4 = d4 as u32 & MASK;
        h0 += (d4 >> 26) as u32 * 5;
        h1 += h0 >> 26;
        h0 &= MASK;
    }

    // Fully carry h.
    let mut c = h1 >> 26;
    h1 &= MASK;
    h2 += c;
    c = h2 >> 26;
    h2 &= MASK;
    h3 += c;
    c = h3 >> 26;
    h3 &= MASK;
    h4 += c;
    c = h4 >> 26;
    h4 &= MASK;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= MASK;
    h1 += c;

    // Compute h - p, and keep it instead of h when h >= p, without branching.
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= MASK;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= MASK;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= MASK;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= MASK;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let use_g = (g4 >> 31).wrapping_sub(1);
    let use_h = !use_g;
    h0 = (h0 & use_h) | (g0 & use_g);
    h1 = (h1 & use_h) | (g1 & use_g);
    h2 = (h2 & use_h) | (g2 & use_g);
    h3 = (h3 & use_h) | (g3 & use_g);
    h4 = (h4 & use_h) | (g4 & use_g);

    // Pack into 128 bits and add the second half of the key.
    let words = [
        h0 | (h1 << 26),
        (h1 >> 6) | (h2 << 20),
        (h2 >> 12) | (h3 << 14),
        (h3 >> 18) | (h4 << 8),
    ];
    let mut tag = [0u8; 16];
    let mut carry = 0u64;
    for (i, word) in words.iter().enumerate() {
        let sum = *word as u64 + le32(key, 16 + 4 * i) as u64 + carry;
        tag[4 * i..4 * i + 4].copy_from_slice(&(sum as u32).to_le_bytes());
        carry = sum >> 32;
    }
    tag
}

fn tag(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 16] {
    let block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block[..32]);

    let padded = ciphertext.len().div_ceil(16) * 16;
    let mut data = Vec::with_capacity(padded + 16);
    data.extend_from_slice(ciphertext);
    data.resize(padded, 0);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305(&poly_key, &data)
}

/// Encrypts `plaintext`, returning the ciphertext followed by the tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    chacha20_xor(key, 1, nonce, &mut out);
    let tag = tag(key, nonce, &out);
    out.extend_from_slice(&tag);
    out
}

/// Checks the tag and decrypts, or returns `None` if the tag is wrong.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
    let split = sealed.len().checked_sub(TAG_LEN)?;
    let (ciphertext, expected) = sealed.split_at(split);
    if !ct_eq(&tag(key, nonce, ciphertext), expected) {
        return None;
    }
    let mut out = ciphertext.to_vec();
    chacha20_xor(key, 1, nonce, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
        bytes.try_into().unwrap()
    }

    #[test]
    fn block_matches_rfc_8439_2_3_2() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce = array(&hex("000000090000004a00000000"));
        assert_eq!(
            chacha20_block(&key, 1, &nonce).to_vec(),
            hex(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e
                 d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )
        );
    }

    #[test]
    fn poly1305_matches_rfc_8439_2_5_2() {
        let key = array(&hex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        ));
        assert_eq!(
            poly1305(&key, b"Cryptographic Forum Research Group").to_vec(),
            hex("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }

    #[test]
    fn poly1305_handles_the_final_reduction() {
        // RFC 8439 appendix A.3, test vectors 6 and 7: inputs that land on or
        // just above the modulus, where the constant-time select matters.
        let mut key = [0u8; 32];
        key[0] = 2;
        key[16..].copy_from_slice(&[0xff; 16]);
        let msg = hex("02000000000000000000000000000000");
        let mut expected = [0u8; 16];
        expected[0] = 0x03;
        assert_eq!(poly1305(&key, &msg), expected);

        let mut key = [0u8; 32];
        key[0] = 1;
        let msg = hex(
            "ffffffffffffffffffffffffffffffff f0ffffffffffffffffffffffffffffff
             11000000000000000000000000000000",
        );
        let mut expected = [0u8; 16];
        expected[0] = 0x05;
        assert_eq!(poly1305(&key, &msg), expected);
    }

    #[test]
    fn aead_round_trips_and_rejects_tampering() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        for len in [0, 1, 15, 16, 17, 63, 64, 65, 1000] {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = seal(&key, &nonce, &plaintext);
            assert_eq!(sealed.len(), len + TAG_LEN);
            assert_eq!(open(&key, &nonce, &sealed).unwrap(), plaintext);
            for i in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[i] ^= 1;
                assert!(open(&key, &nonce, &bad).is_none());
            }
        }
        assert!(open(&key, &nonce, &[0; 15]).is_none());
    }
}
