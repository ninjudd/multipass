//! The age v1 file format (https://age-encryption.org/v1), passphrase
//! recipients only.
//!
//! ```text
//! age-encryption.org/v1
//! -> scrypt <salt> <log_n>
//! <file key wrapped with ChaCha20-Poly1305 under the scrypt key>
//! --- <HMAC-SHA-256 of everything above, up to and including "---">
//! <16-byte nonce><payload in 64 KiB ChaCha20-Poly1305 chunks>
//! ```

use std::fmt;
use std::io;

use crate::crypto::{base64, chacha20poly1305 as aead, ct_eq, random, scrypt::scrypt, sha256};

const INTRO: &[u8] = b"age-encryption.org/v1\n";
const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
const CHUNK: usize = 64 * 1024;

/// scrypt cost `2^18`, which takes 256 MiB and about a third of a second in a
/// release build. It matches the reference age implementation's default.
pub const DEFAULT_WORK_FACTOR: u8 = 18;

/// The highest scrypt cost `decrypt` will attempt, so a hostile file cannot
/// demand hours of work and gigabytes of memory. It matches reference age.
pub const MAX_WORK_FACTOR: u8 = 22;

#[derive(Debug)]
pub enum Error {
    /// The data does not start with an age header.
    NotAge,
    /// The file is encrypted to a public key rather than a passphrase.
    NotPassphrase,
    WorkFactorTooHigh(u8),
    WrongPassphrase,
    /// The header or payload fails to parse or authenticate.
    Damaged,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAge => write!(f, "the store is not an age file"),
            Error::NotPassphrase => {
                write!(
                    f,
                    "the store is encrypted to a public key, not a passphrase"
                )
            }
            Error::WorkFactorTooHigh(n) => write!(
                f,
                "the store asks for scrypt work factor {n}, above the limit of {MAX_WORK_FACTOR}"
            ),
            Error::WrongPassphrase => write!(f, "wrong passphrase, or the store is damaged"),
            Error::Damaged => write!(f, "the store is damaged or has been tampered with"),
        }
    }
}

fn scrypt_key(passphrase: &[u8], salt: &[u8], log_n: u8) -> [u8; 32] {
    let mut full_salt = SCRYPT_LABEL.to_vec();
    full_salt.extend_from_slice(salt);
    let mut key = [0u8; 32];
    scrypt(passphrase, &full_salt, log_n, 8, 1, &mut key);
    key
}

/// The STREAM nonce: an 11-byte big-endian chunk counter, then 1 for the
/// final chunk and 0 for every other.
fn chunk_nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = last as u8;
    nonce
}

pub fn encrypt(passphrase: &[u8], plaintext: &[u8], log_n: u8) -> io::Result<Vec<u8>> {
    let mut file_key = [0u8; 16];
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    random::fill(&mut file_key)?;
    random::fill(&mut salt)?;
    random::fill(&mut nonce)?;

    let wrapped = aead::seal(&scrypt_key(passphrase, &salt, log_n), &[0; 12], &file_key);
    let mut out = INTRO.to_vec();
    out.extend_from_slice(
        format!(
            "-> scrypt {} {log_n}\n{}\n---",
            base64::encode(&salt),
            base64::encode(&wrapped)
        )
        .as_bytes(),
    );
    let mac = sha256::hmac(&sha256::hkdf(&[], &file_key, b"header"), &[&out]);
    out.extend_from_slice(format!(" {}\n", base64::encode(&mac)).as_bytes());

    out.extend_from_slice(&nonce);
    let payload_key = sha256::hkdf(&nonce, &file_key, b"payload");
    // An empty plaintext is still one (empty) final chunk.
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[]]
    } else {
        plaintext.chunks(CHUNK).collect()
    };
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i + 1 == chunks.len();
        out.extend_from_slice(&aead::seal(
            &payload_key,
            &chunk_nonce(i as u64, last),
            chunk,
        ));
    }
    Ok(out)
}

/// Splits off one header line, without its newline.
fn line(data: &[u8]) -> Result<(&str, &[u8]), Error> {
    let end = data
        .iter()
        .position(|&b| b == b'\n')
        .ok_or(Error::Damaged)?;
    let text = std::str::from_utf8(&data[..end]).map_err(|_| Error::Damaged)?;
    Ok((text, &data[end + 1..]))
}

pub fn decrypt(passphrase: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let rest = data.strip_prefix(INTRO).ok_or(Error::NotAge)?;

    let (stanza, rest) = line(rest)?;
    let args: Vec<&str> = stanza
        .strip_prefix("-> ")
        .ok_or(Error::Damaged)?
        .split(' ')
        .collect();
    if args[0] != "scrypt" {
        return Err(Error::NotPassphrase);
    }
    let [_, salt, log_n] = args[..] else {
        return Err(Error::Damaged);
    };
    let salt = base64::decode(salt)
        .filter(|s| s.len() == 16)
        .ok_or(Error::Damaged)?;
    let log_n = parse_log_n(log_n)?;

    let (body, rest) = line(rest)?;
    let wrapped = base64::decode(body)
        .filter(|w| w.len() == 32)
        .ok_or(Error::Damaged)?;

    // An scrypt stanza must be the only one, so the MAC line comes next.
    let (mac_line, payload) = line(rest)?;
    let mac = mac_line
        .strip_prefix("--- ")
        .and_then(base64::decode)
        .filter(|m| m.len() == 32)
        .ok_or(Error::Damaged)?;
    let header_len = data.len() - payload.len() - mac_line.len() - 1 + "---".len();

    let file_key = aead::open(&scrypt_key(passphrase, &salt, log_n), &[0; 12], &wrapped)
        .ok_or(Error::WrongPassphrase)?;
    let expected = sha256::hmac(
        &sha256::hkdf(&[], &file_key, b"header"),
        &[&data[..header_len]],
    );
    if !ct_eq(&expected, &mac) {
        return Err(Error::Damaged);
    }

    if payload.len() < 16 {
        return Err(Error::Damaged);
    }
    let (nonce, mut sealed) = payload.split_at(16);
    let payload_key = sha256::hkdf(nonce, &file_key, b"payload");
    let mut out = Vec::with_capacity(sealed.len());
    let mut counter = 0u64;
    loop {
        let take = sealed.len().min(CHUNK + aead::TAG_LEN);
        let (chunk, remaining) = sealed.split_at(take);
        let last = remaining.is_empty();
        let plain =
            aead::open(&payload_key, &chunk_nonce(counter, last), chunk).ok_or(Error::Damaged)?;
        // Only a file that is empty overall may end with an empty chunk.
        if last && plain.is_empty() && counter > 0 {
            return Err(Error::Damaged);
        }
        out.extend_from_slice(&plain);
        if last {
            return Ok(out);
        }
        sealed = remaining;
        counter += 1;
    }
}

fn parse_log_n(s: &str) -> Result<u8, Error> {
    let canonical = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0');
    let n: u32 = s.parse().ok().filter(|_| canonical).ok_or(Error::Damaged)?;
    if n > MAX_WORK_FACTOR as u32 {
        return Err(Error::WorkFactorTooHigh(n.min(255) as u8));
    }
    Ok(n as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: u8 = 10;

    /// Files written by the reference implementation (the `age` crate,
    /// version 0.12.1) with this passphrase and work factor 10. Their
    /// plaintexts are `pattern(len)` for the lengths in their names.
    const FIXTURE_PASSPHRASE: &[u8] = b"multipass test passphrase";
    const FIXTURES: [(&[u8], usize); 4] = [
        (include_bytes!("../testdata/reference-0.age"), 0),
        (include_bytes!("../testdata/reference-27.age"), 27),
        (include_bytes!("../testdata/reference-65536.age"), 65536),
        (include_bytes!("../testdata/reference-65537.age"), 65537),
    ];

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn decrypts_files_from_the_reference_implementation() {
        for (file, len) in FIXTURES {
            assert_eq!(
                decrypt(FIXTURE_PASSPHRASE, file).unwrap(),
                pattern(len),
                "length {len}"
            );
        }
    }

    #[test]
    fn round_trips_at_chunk_boundaries() {
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 5] {
            let plaintext = pattern(len);
            let file = encrypt(b"pass", &plaintext, FAST).unwrap();
            assert_eq!(decrypt(b"pass", &file).unwrap(), plaintext, "length {len}");
        }
    }

    #[test]
    fn writes_the_header_the_way_age_does() {
        let file = encrypt(b"pass", b"x", FAST).unwrap();
        let text = String::from_utf8_lossy(&file);
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines[0], "age-encryption.org/v1");
        assert!(lines[1].starts_with("-> scrypt "));
        assert!(lines[1].ends_with(" 10"));
        assert_eq!(lines[2].len(), 43);
        assert!(lines[3].starts_with("--- "));
        assert_eq!(lines[3].len(), 4 + 43);
    }

    #[test]
    fn rejects_the_wrong_passphrase() {
        let file = encrypt(b"right", b"secret", FAST).unwrap();
        assert!(matches!(
            decrypt(b"wrong", &file),
            Err(Error::WrongPassphrase)
        ));
        assert!(matches!(
            decrypt(b"wrong", FIXTURES[1].0),
            Err(Error::WrongPassphrase)
        ));
    }

    #[test]
    fn rejects_any_changed_byte() {
        let file = encrypt(b"pass", b"some secret", FAST).unwrap();
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(decrypt(b"pass", &bad).is_err(), "byte {i} changed");
        }
    }

    #[test]
    fn rejects_truncation_and_extension() {
        let file = encrypt(b"pass", &pattern(CHUNK + 10), FAST).unwrap();
        let header_and_first_chunk = file.len() - (10 + aead::TAG_LEN);
        for len in [file.len() - 1, header_and_first_chunk, file.len() - 17] {
            assert!(matches!(
                decrypt(b"pass", &file[..len]),
                Err(Error::Damaged)
            ));
        }
        let mut longer = file.clone();
        longer.push(0);
        assert!(matches!(decrypt(b"pass", &longer), Err(Error::Damaged)));
    }

    #[test]
    fn refuses_excessive_work_before_doing_it() {
        let file = encrypt(b"pass", b"x", FAST).unwrap();
        let text = String::from_utf8_lossy(&file).replacen(" 10\n", " 23\n", 1);
        assert!(matches!(
            decrypt(b"pass", text.as_bytes()),
            Err(Error::WorkFactorTooHigh(23))
        ));
    }

    #[test]
    fn rejects_other_files() {
        assert!(matches!(decrypt(b"pass", b"hello"), Err(Error::NotAge)));
        let x25519 = b"age-encryption.org/v1\n-> X25519 abc\nabc\n--- abc\n";
        assert!(matches!(
            decrypt(b"pass", x25519),
            Err(Error::NotPassphrase)
        ));
    }

    #[test]
    fn parses_only_canonical_work_factors() {
        assert_eq!(parse_log_n("18").unwrap(), 18);
        for bad in ["", "018", "+18", "1 8", "x"] {
            assert!(parse_log_n(bad).is_err(), "{bad:?}");
        }
        assert!(matches!(
            parse_log_n("99999"),
            Err(Error::WorkFactorTooHigh(255))
        ));
    }
}
