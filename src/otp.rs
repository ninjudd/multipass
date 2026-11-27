//! One-time passwords from `otpauth://totp/` URIs, the format that
//! authenticator apps read from QR codes.

use std::fmt;

use crate::crypto::hotp::totp;
use crate::crypto::sha1::Sha1;
use crate::crypto::sha256::Sha256;
use crate::crypto::sha512::Sha512;
use crate::crypto::{base32, ct_eq};

const PREFIX: &str = "otpauth://";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A checked one-time password: its setup key and how to turn it into codes.
#[derive(Debug, PartialEq, Eq)]
pub struct Otp {
    key: Vec<u8>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotOtpauth,
    Hotp,
    NotTotp,
    MissingSecret,
    BadSecret,
    BadAlgorithm,
    BadDigits,
    BadPeriod,
    Repeated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotOtpauth => write!(f, "not an otpauth:// URI or a base32 setup key"),
            Error::Hotp => write!(
                f,
                "counter-based (hotp) one-time passwords are not supported; use a totp URI"
            ),
            Error::NotTotp => write!(f, "the otpauth URI must be otpauth://totp/…"),
            Error::MissingSecret => write!(f, "the otpauth URI has no secret"),
            Error::BadSecret => write!(f, "the setup key is not valid base32"),
            Error::BadAlgorithm => write!(f, "the algorithm must be SHA1, SHA256 or SHA512"),
            Error::BadDigits => write!(f, "digits must be 6, 7 or 8"),
            Error::BadPeriod => write!(f, "period must be 1 to 300 seconds"),
            Error::Repeated => write!(f, "the otpauth URI repeats a parameter"),
        }
    }
}

impl Otp {
    /// Parses and checks an `otpauth://totp/` URI. Parameters other than
    /// `secret`, `algorithm`, `digits`, and `period` are kept in the stored
    /// URI but ignored here.
    pub fn parse(uri: &str) -> Result<Self, Error> {
        let rest = strip_prefix_ignoring_case(uri, PREFIX).ok_or(Error::NotOtpauth)?;
        let (kind, rest) = rest.split_once('/').ok_or(Error::NotTotp)?;
        if kind.eq_ignore_ascii_case("hotp") {
            return Err(Error::Hotp);
        }
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::NotTotp);
        }
        let query = rest.split_once('?').map_or("", |(_, query)| query);

        let mut secret = None;
        let mut algorithm = None;
        let mut digits = None;
        let mut period = None;
        // Splitting on `&` and `=` branches only where those delimiters fall;
        // every base32 character in the secret takes the same path.
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let slot = match name {
                "secret" => &mut secret,
                "algorithm" => &mut algorithm,
                "digits" => &mut digits,
                "period" => &mut period,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(Error::Repeated);
            }
        }

        // The secret is not percent-decoded, which would branch on its
        // characters; base32 never needs escaping.
        let key = base32::decode(secret.ok_or(Error::MissingSecret)?)
            .filter(|key| !key.is_empty())
            .ok_or(Error::BadSecret)?;
        let algorithm = match algorithm.map(str::to_ascii_uppercase).as_deref() {
            None | Some("SHA1") => Algorithm::Sha1,
            Some("SHA256") => Algorithm::Sha256,
            Some("SHA512") => Algorithm::Sha512,
            Some(_) => return Err(Error::BadAlgorithm),
        };
        let digits = match digits {
            None => 6,
            Some(d) => d
                .parse()
                .ok()
                .filter(|d| (6..=8).contains(d))
                .ok_or(Error::BadDigits)?,
        };
        let period = match period {
            None => 30,
            Some(p) => p
                .parse()
                .ok()
                .filter(|p| (1..=300).contains(p))
                .ok_or(Error::BadPeriod)?,
        };
        Ok(Self {
            key,
            algorithm,
            digits,
            period,
        })
    }

    /// The code at `unix_seconds`, zero-padded to the URI's digit count.
    pub fn code(&self, unix_seconds: u64) -> String {
        let (key, period, digits) = (&self.key, self.period, self.digits);
        let code = match self.algorithm {
            Algorithm::Sha1 => totp::<Sha1>(key, unix_seconds, period, digits),
            Algorithm::Sha256 => totp::<Sha256>(key, unix_seconds, period, digits),
            Algorithm::Sha512 => totp::<Sha512>(key, unix_seconds, period, digits),
        };
        format!("{code:0width$}", width = digits as usize)
    }

    /// Seconds until the code at `unix_seconds` changes.
    pub fn seconds_left(&self, unix_seconds: u64) -> u64 {
        self.period - unix_seconds % self.period
    }
}

/// Turns what you paste into a URI to store: an `otpauth://` URI is checked
/// and kept exactly as given, and a bare base32 key becomes
/// `otpauth://totp/<name>?secret=<KEY>`.
pub fn setup_uri(input: &str, name: &str) -> Result<String, Error> {
    if strip_prefix_ignoring_case(input, PREFIX).is_some() {
        Otp::parse(input)?;
        return Ok(input.to_string());
    }
    let key = base32::decode(input)
        .filter(|key| !key.is_empty())
        .ok_or(Error::BadSecret)?;
    Ok(format!(
        "{PREFIX}totp/{}?secret={}",
        percent_encode(name),
        base32::encode(&key)
    ))
}

/// Compares the prefix in constant time, because a bare setup key passes
/// through here too.
fn strip_prefix_ignoring_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.as_bytes().get(..prefix.len())?;
    let lowered: Vec<u8> = head.iter().map(|b| b | 0x20).collect();
    let wanted: Vec<u8> = prefix.bytes().map(|b| b | 0x20).collect();
    if ct_eq(&lowered, &wanted) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

/// Percent-encodes every byte outside RFC 3986's unreserved characters.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `JBSWY3DPEHPK3PXP` decodes to `Hello!` followed by `de ad be ef`.
    const KEY: &str = "JBSWY3DPEHPK3PXP";

    #[test]
    fn accepts_defaults_and_each_listed_value() {
        let otp = Otp::parse(&format!(
            "otpauth://totp/GitHub:me?secret={KEY}&issuer=GitHub"
        ))
        .unwrap();
        assert_eq!(
            (otp.algorithm, otp.digits, otp.period),
            (Algorithm::Sha1, 6, 30)
        );
        assert_eq!(otp.key, b"Hello!\xde\xad\xbe\xef");

        for (query, expected) in [
            ("algorithm=SHA256", (Algorithm::Sha256, 6, 30)),
            ("algorithm=sha512", (Algorithm::Sha512, 6, 30)),
            ("digits=7", (Algorithm::Sha1, 7, 30)),
            ("digits=8&period=60", (Algorithm::Sha1, 8, 60)),
            ("period=1", (Algorithm::Sha1, 6, 1)),
            ("period=300", (Algorithm::Sha1, 6, 300)),
        ] {
            let otp = Otp::parse(&format!("otpauth://totp/x?secret={KEY}&{query}")).unwrap();
            assert_eq!((otp.algorithm, otp.digits, otp.period), expected, "{query}");
        }
    }

    #[test]
    fn rejects_uris_it_cannot_use() {
        for (uri, error) in [
            (
                format!("otpauth://hotp/x?secret={KEY}&counter=0"),
                Error::Hotp,
            ),
            (format!("otpauth://yotp/x?secret={KEY}"), Error::NotTotp),
            ("otpauth://totp/x?issuer=x".into(), Error::MissingSecret),
            ("otpauth://totp/x?secret=".into(), Error::BadSecret),
            (
                "otpauth://totp/x?secret=NOT-BASE32".into(),
                Error::BadSecret,
            ),
            (
                format!("otpauth://totp/x?secret={KEY}&digits=9"),
                Error::BadDigits,
            ),
            (
                format!("otpauth://totp/x?secret={KEY}&digits=5"),
                Error::BadDigits,
            ),
            (
                format!("otpauth://totp/x?secret={KEY}&period=0"),
                Error::BadPeriod,
            ),
            (
                format!("otpauth://totp/x?secret={KEY}&period=301"),
                Error::BadPeriod,
            ),
            (
                format!("otpauth://totp/x?secret={KEY}&algorithm=MD5"),
                Error::BadAlgorithm,
            ),
            (
                format!("otpauth://totp/x?secret={KEY}&secret={KEY}"),
                Error::Repeated,
            ),
            (
                format!("https://example.com/?secret={KEY}"),
                Error::NotOtpauth,
            ),
        ] {
            assert_eq!(Otp::parse(&uri), Err(error), "{uri}");
        }
    }

    #[test]
    fn codes_are_zero_padded_to_the_digit_count() {
        // RFC 6238's SHA-1 seed at time 1111111109 gives 07081804.
        let seed = base32::encode(b"12345678901234567890");
        let otp = Otp::parse(&format!("otpauth://totp/x?secret={seed}&digits=8")).unwrap();
        assert_eq!(otp.code(1111111109), "07081804");
        assert_eq!(otp.seconds_left(1111111109), 1);
        assert_eq!(otp.seconds_left(1111111110), 30);
    }

    #[test]
    fn a_bare_key_becomes_a_uri_under_any_entry_name() {
        for name in ["github.com", "Chase Bank #2", "a?b", "a/b", "100%", "é"] {
            let uri = setup_uri("jbsw y3dp ehpk 3pxp", name).unwrap();
            let otp = Otp::parse(&uri).unwrap();
            assert_eq!(otp.key, b"Hello!\xde\xad\xbe\xef", "{name}");
            assert!(uri.ends_with(&format!("?secret={KEY}")), "{uri}");
        }
        assert_eq!(
            setup_uri(KEY, "Chase Bank #2").unwrap(),
            format!("otpauth://totp/Chase%20Bank%20%232?secret={KEY}")
        );
    }

    #[test]
    fn a_uri_is_kept_exactly_as_given() {
        let uri = format!("OTPAUTH://totp/GitHub%3Ame?issuer=GitHub&secret={KEY}&image=x");
        assert_eq!(setup_uri(&uri, "ignored").unwrap(), uri);
        assert_eq!(
            setup_uri("otpauth://totp/x?secret=0", "x"),
            Err(Error::BadSecret)
        );
        assert_eq!(setup_uri("not base32!", "x"), Err(Error::BadSecret));
    }
}
