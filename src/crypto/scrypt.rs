//! scrypt (RFC 7914), built on Salsa20/8 and PBKDF2-HMAC-SHA-256.

use super::sha256::pbkdf2;

/// Derives `out.len()` bytes from `password` and `salt` with cost
/// `N = 2^log_n`, block size `r` and parallelism `p`.
pub fn scrypt(password: &[u8], salt: &[u8], log_n: u8, r: usize, p: usize, out: &mut [u8]) {
    assert!((1..32).contains(&log_n), "scrypt log_n out of range");
    let n = 1usize << log_n;
    let words = 32 * r;

    let mut b = vec![0u8; 128 * r * p];
    pbkdf2(password, salt, 1, &mut b);

    let mut v = vec![0u32; words * n];
    let mut x = vec![0u32; words];
    let mut y = vec![0u32; words];
    for block in b.chunks_mut(128 * r) {
        romix(block, r, n, &mut v, &mut x, &mut y);
    }

    pbkdf2(password, &b, 1, out);
}

fn romix(block: &mut [u8], r: usize, n: usize, v: &mut [u32], x: &mut [u32], y: &mut [u32]) {
    let words = 32 * r;
    for (w, bytes) in x.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for i in 0..n {
        v[i * words..(i + 1) * words].copy_from_slice(x);
        block_mix(x, y, r);
    }
    for _ in 0..n {
        // Integerify: the first word of the last 64-byte block, mod N.
        let j = x[(2 * r - 1) * 16] as usize & (n - 1);
        for (x, v) in x.iter_mut().zip(&v[j * words..(j + 1) * words]) {
            *x ^= v;
        }
        block_mix(x, y, r);
    }
    for (bytes, w) in block.chunks_exact_mut(4).zip(x.iter()) {
        bytes.copy_from_slice(&w.to_le_bytes());
    }
}

fn block_mix(b: &mut [u32], y: &mut [u32], r: usize) {
    let mut t = [0u32; 16];
    t.copy_from_slice(&b[(2 * r - 1) * 16..2 * r * 16]);
    for i in 0..2 * r {
        for (t, b) in t.iter_mut().zip(&b[i * 16..(i + 1) * 16]) {
            *t ^= b;
        }
        salsa20_8(&mut t);
        // Even blocks go to the first half of the output, odd to the second.
        let dst = if i % 2 == 0 { i / 2 } else { r + i / 2 };
        y[dst * 16..(dst + 1) * 16].copy_from_slice(&t);
    }
    b.copy_from_slice(y);
}

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    for _ in 0..4 {
        // Columns.
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);
        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);
        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);
        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);
        // Rows.
        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);
        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);
        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);
        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }
    for (b, x) in b.iter_mut().zip(x) {
        *b = b.wrapping_add(x);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn matches_rfc_7914_vectors() {
        let mut out = [0u8; 64];
        scrypt(b"", b"", 4, 1, 1, &mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442
                 fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
            )
        );
        scrypt(b"password", b"NaCl", 10, 8, 16, &mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162
                 2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
            )
        );
    }

    #[test]
    fn matches_rfc_7914_salsa20_8_vector() {
        let input = hex(
            "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d
             ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e",
        );
        let mut block = [0u32; 16];
        for (w, bytes) in block.iter_mut().zip(input.chunks_exact(4)) {
            *w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        salsa20_8(&mut block);
        let output: Vec<u8> = block.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(
            output,
            hex(
                "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29
                 b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81"
            )
        );
    }
}
