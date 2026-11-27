//! HOTP (RFC 4226) and TOTP (RFC 6238), over any hash HMAC supports.

use super::ct_eq_mask;
use super::hmac::{Digest, hmac};

/// The HOTP value for `counter`, reduced to `digits` decimal digits.
pub fn hotp<D: Digest>(key: &[u8], counter: u64, digits: u32) -> u32 {
    let mac = hmac::<D>(key, &[&counter.to_be_bytes()]);
    let mac = mac.as_ref();

    // Dynamic truncation (RFC 4226 § 5.4) reads four bytes at an offset taken
    // from the MAC itself, which is secret, so every candidate offset is read
    // and only the matching one is kept.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let mut word = [0u8; 4];
    for start in 0..=mac.len() - 4 {
        let hit = ct_eq_mask(start, offset) as u8;
        for (w, m) in word.iter_mut().zip(&mac[start..start + 4]) {
            *w |= m & hit;
        }
    }
    (u32::from_be_bytes(word) & 0x7fff_ffff) % 10u32.pow(digits)
}

/// The TOTP value at `unix_seconds` for a code that changes every `period`
/// seconds.
pub fn totp<D: Digest>(key: &[u8], unix_seconds: u64, period: u64, digits: u32) -> u32 {
    hotp::<D>(key, unix_seconds / period, digits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha1::Sha1;
    use crate::crypto::sha256::Sha256;
    use crate::crypto::sha512::Sha512;

    const RFC_SEED: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_matches_rfc_4226_appendix_d() {
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, code) in expected.into_iter().enumerate() {
            assert_eq!(hotp::<Sha1>(RFC_SEED, counter as u64, 6), code, "{counter}");
        }
    }

    #[test]
    fn totp_matches_rfc_6238_appendix_b() {
        // Each algorithm uses its own seed, from the reference code in
        // Appendix A: the 20-byte seed repeated to the hash's output length.
        let seed32 = RFC_SEED.repeat(2)[..32].to_vec();
        let seed64 = RFC_SEED.repeat(4)[..64].to_vec();
        let rows: [(u64, u32, u32, u32); 6] = [
            (59, 94287082, 46119246, 90693936),
            (1111111109, 7081804, 68084774, 25091201),
            (1111111111, 14050471, 67062674, 99943326),
            (1234567890, 89005924, 91819424, 93441116),
            (2000000000, 69279037, 90698825, 38618901),
            (20000000000, 65353130, 77737706, 47863826),
        ];
        for (time, sha1, sha256, sha512) in rows {
            let codes = (
                totp::<Sha1>(RFC_SEED, time, 30, 8),
                totp::<Sha256>(&seed32, time, 30, 8),
                totp::<Sha512>(&seed64, time, 30, 8),
            );
            assert_eq!(codes, (sha1, sha256, sha512), "time {time}");
        }
    }
}
