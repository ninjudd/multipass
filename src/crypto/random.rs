//! Random bytes from the operating system's generator.

use std::fs::File;
use std::io::{self, Read};

/// Fills `buf` from `/dev/urandom`, which on macOS and Linux is the kernel's
/// cryptographic generator and never blocks once the system has booted.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buf)
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
}
