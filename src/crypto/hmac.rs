//! HMAC (RFC 2104) over any of the hashes in this crate, and the block
//! buffering and padding that SHA-1, SHA-256, and SHA-512 share (FIPS 180-4
//! § 5.1).

/// A hash function that HMAC can use.
pub trait Digest: Sized {
    /// The input block size, which HMAC pads its key to.
    const BLOCK_LEN: usize;
    type Output: AsRef<[u8]>;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;

    fn digest(data: &[u8]) -> Self::Output {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// The longest block of any hash here, SHA-512's.
const MAX_BLOCK_LEN: usize = 128;

/// HMAC over the concatenation of `parts`.
pub fn hmac<D: Digest>(key: &[u8], parts: &[&[u8]]) -> D::Output {
    let mut block = [0u8; MAX_BLOCK_LEN];
    let block = &mut block[..D::BLOCK_LEN];
    if key.len() > D::BLOCK_LEN {
        let hashed = D::digest(key);
        block[..hashed.as_ref().len()].copy_from_slice(hashed.as_ref());
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut pad = [0u8; MAX_BLOCK_LEN];
    let pad = &mut pad[..D::BLOCK_LEN];
    for (p, b) in pad.iter_mut().zip(block.iter()) {
        *p = b ^ 0x36;
    }
    let mut inner = D::new();
    inner.update(pad);
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();

    for (p, b) in pad.iter_mut().zip(block.iter()) {
        *p = b ^ 0x5c;
    }
    let mut outer = D::new();
    outer.update(pad);
    outer.update(inner.as_ref());
    outer.finalize()
}

/// Collects input into `B`-byte blocks for a hash's compression function.
pub struct BlockBuffer<const B: usize> {
    buffer: [u8; B],
    buffered: usize,
    length: u128,
}

impl<const B: usize> BlockBuffer<B> {
    pub fn new() -> Self {
        Self {
            buffer: [0; B],
            buffered: 0,
            length: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8; B])) {
        self.length = self.length.wrapping_add(data.len() as u128);
        if self.buffered > 0 {
            let take = (B - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < B {
                return;
            }
            compress(&self.buffer);
            self.buffered = 0;
        }
        let mut blocks = data.chunks_exact(B);
        for block in &mut blocks {
            compress(block.try_into().expect("chunks_exact yields whole blocks"));
        }
        let rest = blocks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Pads the message with a 1 bit, zeros, and its length in bits as a
    /// big-endian number of `length_len` bytes, which is 8 for SHA-1 and
    /// SHA-256 and 16 for SHA-512.
    pub fn finish(mut self, length_len: usize, mut compress: impl FnMut(&[u8; B])) {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        self.update(&[0x80], &mut compress);
        while self.buffered != B - length_len {
            self.update(&[0], &mut compress);
        }
        self.update(&bits[bits.len() - length_len..], &mut compress);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;
    use crate::crypto::sha256::Sha256;
    use crate::crypto::sha512::Sha512;

    const LONG_KEY_MESSAGE: [&[u8]; 2] = [
        b"Test Using Larger Than Block-",
        b"Size Key - Hash Key First",
    ];

    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        // Test case 1.
        assert_eq!(
            hmac::<Sha256>(&[0x0b; 20], &[b"Hi There"]).to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // Test case 6: a key longer than the block size is hashed first.
        assert_eq!(
            hmac::<Sha256>(&[0xaa; 131], &LONG_KEY_MESSAGE).to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn hmac_sha512_matches_rfc_4231() {
        // Test case 1.
        assert_eq!(
            hmac::<Sha512>(&[0x0b; 20], &[b"Hi There"]).to_vec(),
            hex(concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ))
        );
        // Test case 6: the 131-byte key is longer than SHA-512's 128-byte
        // block, so it is hashed first; padding it to 64 bytes would differ.
        assert_eq!(
            hmac::<Sha512>(&[0xaa; 131], &LONG_KEY_MESSAGE).to_vec(),
            hex(concat!(
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
                "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
            ))
        );
    }
}
