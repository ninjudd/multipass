//! The store: every entry, kept as a small text document inside one age file.
//!
//! The text is meant to be read by a person recovering the store with plain
//! `age -d`:
//!
//! ```text
//! multipass 3
//! github.com
//!     modified 1764160000123
//!     secret hunter2
//!     username octocat
//!     otp otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP
//!     previous-secret 1764150000000 hunter1
//! old-bank
//!     modified 1764160000456
//!     deleted
//!     previous-secret 1764160000456 correct horse battery staple
//! ```
//!
//! An unindented line names an entry. Each line under it is indented with
//! one tab (shown as spaces above) and holds a field name, one space, and the
//! value. Names and values escape backslash, newline, tab and carriage return
//! as `\\`, `\n`, `\t` and `\r`.
//!
//! Every entry starts with `modified`, the time in milliseconds since the
//! Unix epoch when it last changed, which is what lets two copies of the
//! store merge entry by entry. A live entry has a `secret`, an `otp`, or
//! both. A removed entry is a tombstone, marked `deleted`, so a merge can
//! tell a removal from an entry it has never seen. `previous-secret` and
//! `previous-otp` keep the values an entry used to hold, each after the time
//! it was replaced. Formats 1 and 2, which multipass still reads, have
//! neither `modified` nor history, and format 1 has no `otp` field.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::age;
use crate::otp::Otp;

const HEADER: &str = "multipass 3";
const FORMAT_2: &str = "multipass 2";
const FORMAT_1: &str = "multipass 1";

/// A day in milliseconds, the unit of every stamp.
pub const DAY: u64 = 24 * 60 * 60 * 1000;

/// How long a tombstone stays, so a removal reaches every copy of the store
/// before it is forgotten.
const TOMBSTONE_DAYS: u64 = 120;

/// How long a tombstone keeps the removed entry's secrets, so `rm` can be
/// undone the way a "recently deleted" folder allows.
const REMOVED_SECRET_DAYS: u64 = 30;

/// A live entry keeps every value replaced within this many days, and at
/// least the newest `HISTORY_KEPT` of each kind, whichever keeps more.
const HISTORY_DAYS: u64 = 365;
const HISTORY_KEPT: usize = 10;

/// One account: its secret, its one-time password, or both, and what goes
/// with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub secret: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    /// An `otpauth://totp/` URI, kept exactly as it was entered.
    pub otp: Option<String>,
}

/// A value an entry used to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Previous {
    /// When the value stopped being current. For a value kept from the
    /// losing side of a merge, this is when that side last changed.
    pub replaced: u64,
    pub value: String,
}

/// The earlier secrets and setup keys of one entry, each list newest first
/// and holding each value once, at the latest time it was replaced. The
/// entry's current value never appears in its own history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    pub secrets: Vec<Previous>,
    pub otps: Vec<Previous>,
}

/// One name's state: a live entry or a tombstone, when it last changed, and
/// its history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub modified: u64,
    /// `None` is a tombstone.
    pub entry: Option<Entry>,
    pub history: History,
}

/// What `to_text` leaves out, each as a stamp before which it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cutoffs {
    /// Tombstones modified before this are dropped, with their history.
    pub tombstones: u64,
    /// Tombstones modified before this keep their marker but lose their
    /// history, so a removed secret is gone for good.
    pub removed_secrets: u64,
    /// History replaced before this is dropped, past the newest ten.
    pub history: u64,
}

impl Cutoffs {
    /// The cutoffs for a store written at `now`.
    pub fn at(now: u64) -> Self {
        Cutoffs {
            tombstones: now.saturating_sub(TOMBSTONE_DAYS * DAY),
            removed_secrets: now.saturating_sub(REMOVED_SECRET_DAYS * DAY),
            history: now.saturating_sub(HISTORY_DAYS * DAY),
        }
    }
}

/// True when a change stamped `stamp` is more than a day ahead of `now`,
/// because some machine's clock ran fast.
pub fn dated_in_future(stamp: u64, now: u64) -> bool {
    stamp > now.saturating_add(DAY)
}

impl Version {
    /// The version's text without its name line or history, which is what
    /// breaks a tie between two versions with the same stamp.
    fn current_text(&self) -> String {
        let mut out = format!("\tmodified {}\n", self.modified);
        match &self.entry {
            None => out.push_str("\tdeleted\n"),
            Some(entry) => {
                let fields = [
                    ("secret", entry.secret.as_ref()),
                    ("username", entry.username.as_ref()),
                    ("otp", entry.otp.as_ref()),
                    ("notes", entry.notes.as_ref()),
                ];
                for (field, value) in fields {
                    if let Some(value) = value {
                        out.push_str(&format!("\t{field} {}\n", escape(value)));
                    }
                }
            }
        }
        out
    }

    /// Restores the invariant `History` describes.
    fn normalize(&mut self) {
        let entry = self.entry.as_ref();
        normalize(
            &mut self.history.secrets,
            entry.and_then(|e| e.secret.as_deref()),
        );
        normalize(&mut self.history.otps, entry.and_then(|e| e.otp.as_deref()));
    }

    /// Keeps whichever version is newer, and makes every secret and setup key
    /// either one held part of the result's history, so a merge never drops
    /// one. A value from the losing side is dated by that side's stamp, never
    /// the winner's, so the result does not depend on the order of merging.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the vault-key plan is the first caller")
    )]
    fn join(&self, other: &Version) -> Version {
        let winner =
            if (self.modified, self.current_text()) >= (other.modified, other.current_text()) {
                self
            } else {
                other
            };
        let mut history = History::default();
        for version in [self, other] {
            history
                .secrets
                .extend(version.history.secrets.iter().cloned());
            history.otps.extend(version.history.otps.iter().cloned());
            version.held_as_history(version.modified, &mut history);
        }
        let mut joined = Version {
            modified: winner.modified,
            entry: winner.entry.clone(),
            history,
        };
        joined.normalize();
        joined
    }

    /// Adds the entry's current secret and setup key to `history`, dated
    /// `replaced`.
    fn held_as_history(&self, replaced: u64, history: &mut History) {
        let Some(entry) = &self.entry else { return };
        for (value, list) in [
            (&entry.secret, &mut history.secrets),
            (&entry.otp, &mut history.otps),
        ] {
            if let Some(value) = value {
                list.push(Previous {
                    replaced,
                    value: value.clone(),
                });
            }
        }
    }
}

/// Sorts `list` newest first, keeps each value once at its latest time, and
/// drops the value that is current again.
fn normalize(list: &mut Vec<Previous>, current: Option<&str>) {
    list.retain(|p| Some(p.value.as_str()) != current);
    list.sort_by(|a, b| a.value.cmp(&b.value).then(b.replaced.cmp(&a.replaced)));
    list.dedup_by(|later, kept| later.value == kept.value);
    list.sort_by(|a, b| b.replaced.cmp(&a.replaced).then(a.value.cmp(&b.value)));
}

/// Every entry, keyed by name. Names live inside the encrypted file, so the
/// file on disk does not reveal which accounts it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Store {
    versions: BTreeMap<String, Version>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// The live entry named `name`; a tombstone reads as no entry.
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.versions.get(name)?.entry.as_ref()
    }

    /// The version named `name`, live or removed, with its history.
    pub fn version(&self, name: &str) -> Option<&Version> {
        self.versions.get(name)
    }

    /// Adds or replaces an entry, stamped `stamp`, returning the one it
    /// replaced. The replaced entry's secret and setup key join the history.
    pub fn insert(&mut self, name: impl Into<String>, entry: Entry, stamp: u64) -> Option<Entry> {
        self.put(name.into(), Some(entry), stamp)
    }

    /// Replaces a live entry with a tombstone stamped `stamp`, which keeps
    /// the entry's secrets as history until `Cutoffs::removed_secrets`.
    pub fn remove(&mut self, name: &str, stamp: u64) -> Option<Entry> {
        self.get(name)?;
        self.put(name.into(), None, stamp)
    }

    fn put(&mut self, name: String, entry: Option<Entry>, stamp: u64) -> Option<Entry> {
        if let Some(old) = self.versions.get(&name) {
            // History dated after `modified` would make the text unreadable.
            assert!(stamp >= old.modified, "a change must not predate {name}'s");
        }
        let mut history = History::default();
        let old = self.versions.remove(&name).and_then(|old| {
            old.held_as_history(stamp, &mut history);
            history.secrets.extend(old.history.secrets);
            history.otps.extend(old.history.otps);
            old.entry
        });
        let mut version = Version {
            modified: stamp,
            entry,
            history,
        };
        version.normalize();
        self.versions.insert(name, version);
        old
    }

    /// Live entry names in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.versions
            .iter()
            .filter(|(_, v)| v.entry.is_some())
            .map(|(name, _)| name.as_str())
    }

    /// The largest `modified` in the store, tombstones included.
    pub fn newest(&self) -> u64 {
        self.versions
            .values()
            .map(|v| v.modified)
            .max()
            .unwrap_or(0)
    }

    /// The stamp for a change made at wall-clock time `now` to this store:
    /// past every stamp the store holds, so a change made after seeing
    /// another always wins over it, even when the clocks disagree.
    pub fn stamp(&self, now: u64) -> u64 {
        now.max(self.newest() + 1)
    }

    /// Combines stores entry by entry, keeping each name's newest version.
    /// The result is the same in any order and any grouping, and merging a
    /// store with itself changes nothing.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the vault-key plan is the first caller")
    )]
    pub fn merge(stores: &[Store]) -> Store {
        let mut merged = Store::new();
        for store in stores {
            for (name, version) in &store.versions {
                let joined = match merged.versions.get(name) {
                    Some(seen) => seen.join(version),
                    None => version.clone(),
                };
                merged.versions.insert(name.clone(), joined);
            }
        }
        merged
    }

    /// Writes format 3, leaving out what `cutoffs` has expired.
    pub fn to_text(&self, cutoffs: Cutoffs) -> String {
        let mut out = format!("{HEADER}\n");
        for (name, version) in &self.versions {
            let removed = version.entry.is_none();
            if removed && version.modified < cutoffs.tombstones {
                continue;
            }
            out.push_str(&escape(name));
            out.push('\n');
            out.push_str(&version.current_text());
            if removed && version.modified < cutoffs.removed_secrets {
                continue;
            }
            for (field, list) in [
                ("previous-secret", &version.history.secrets),
                ("previous-otp", &version.history.otps),
            ] {
                let kept = list
                    .iter()
                    .enumerate()
                    .take_while(|(i, p)| *i < HISTORY_KEPT || p.replaced >= cutoffs.history);
                for (_, previous) in kept {
                    out.push_str(&format!(
                        "\t{field} {} {}\n",
                        previous.replaced,
                        escape(&previous.value)
                    ));
                }
            }
        }
        out
    }

    pub fn from_text(text: &str) -> Result<Self, Error> {
        // Earlier versions of multipass wrote the store as one JSON object.
        if text.starts_with('{') {
            return Err(Error::JsonFormat);
        }
        let body = text.strip_suffix('\n').ok_or(Error::Format { line: 1 })?;
        let mut lines = body.split('\n').zip(1..);

        let format = match lines.next() {
            Some((HEADER, _)) => 3,
            Some((FORMAT_2, _)) => 2,
            Some((FORMAT_1, _)) => 1,
            Some((first, _)) if first.starts_with("multipass ") => {
                return Err(Error::UnsupportedFormat(first["multipass ".len()..].into()));
            }
            _ => return Err(Error::Format { line: 1 }),
        };

        let mut store = Store::new();
        let mut pending: Option<Pending> = None;
        for (line, n) in lines {
            if let Some(field) = line.strip_prefix('\t') {
                let entry = pending.as_mut().ok_or(Error::Format { line: n })?;
                entry
                    .field(format, field)
                    .ok_or(Error::Format { line: n })?;
            } else {
                if let Some(done) = pending.take() {
                    done.finish(&mut store)?;
                }
                let name = unescape(line)
                    .filter(|name| !name.is_empty())
                    .ok_or(Error::Format { line: n })?;
                pending = Some(Pending::new(n, name, format));
            }
        }
        if let Some(done) = pending {
            done.finish(&mut store)?;
        }
        Ok(store)
    }

    /// Encrypts the store with `passphrase` at scrypt cost `2^work_factor`.
    pub fn encrypt(
        &self,
        passphrase: &str,
        work_factor: u8,
        cutoffs: Cutoffs,
    ) -> Result<Vec<u8>, Error> {
        age::encrypt(
            passphrase.as_bytes(),
            self.to_text(cutoffs).as_bytes(),
            work_factor,
        )
        .map_err(Error::Io)
    }

    pub fn decrypt(passphrase: &str, file: &[u8]) -> Result<Self, Error> {
        let plaintext = age::decrypt(passphrase.as_bytes(), file).map_err(Error::Age)?;
        let text = String::from_utf8(plaintext).map_err(|_| Error::NotText)?;
        Self::from_text(&text)
    }

    pub fn load(path: &Path, passphrase: &str) -> Result<Self, Error> {
        Self::decrypt(passphrase, &fs::read(path).map_err(Error::Io)?)
    }

    /// Encrypts the store and replaces the file at `path` atomically: the new
    /// ciphertext goes to a temporary file beside it, which is then renamed
    /// over the old one, so a crash never leaves a half-written store.
    pub fn save(
        &self,
        path: &Path,
        passphrase: &str,
        work_factor: u8,
        cutoffs: Cutoffs,
    ) -> Result<(), Error> {
        let file = self.encrypt(passphrase, work_factor, cutoffs)?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            create_private_dir(dir).map_err(Error::Io)?;
        }
        let tmp = path.with_extension("age.tmp");
        let result = write_private(&tmp, &file).and_then(|()| fs::rename(&tmp, path));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(Error::Io)
    }
}

/// An entry being read, checked field by field as its lines arrive.
struct Pending {
    line: usize,
    name: String,
    /// Formats 1 and 2 have no stamps, so their entries read as `modified 0`
    /// and any later change wins over them.
    modified: Option<u64>,
    deleted: bool,
    entry: Entry,
    history: History,
}

impl Pending {
    fn new(line: usize, name: String, format: u8) -> Self {
        Pending {
            line,
            name,
            modified: (format < 3).then_some(0),
            deleted: false,
            entry: Entry {
                secret: None,
                username: None,
                notes: None,
                otp: None,
            },
            history: History::default(),
        }
    }

    /// Reads one field line, without its tab, or returns `None` when the line
    /// is not valid where it stands.
    fn field(&mut self, format: u8, field: &str) -> Option<()> {
        if format == 3 && self.modified.is_none() {
            let value = field.strip_prefix("modified ")?;
            self.modified = Some(parse_stamp(value)?);
            return Some(());
        }
        let has_fields = self.entry.secret.is_some()
            || self.entry.username.is_some()
            || self.entry.notes.is_some()
            || self.entry.otp.is_some();
        if format == 3 && field == "deleted" {
            if self.deleted || has_fields {
                return None;
            }
            self.deleted = true;
            return Some(());
        }
        let (key, value) = field.split_once(' ')?;
        if format == 3 && key.starts_with("previous-") {
            let (replaced, value) = value.split_once(' ')?;
            let replaced = parse_stamp(replaced).filter(|r| Some(*r) <= self.modified)?;
            let value = unescape(value).filter(|v| !v.is_empty())?;
            let list = match key {
                "previous-secret" => &mut self.history.secrets,
                "previous-otp" if Otp::parse(&value).is_ok() => &mut self.history.otps,
                _ => return None,
            };
            list.push(Previous { replaced, value });
            return Some(());
        }
        if self.deleted {
            return None;
        }
        let slot = match key {
            "secret" => &mut self.entry.secret,
            "username" => &mut self.entry.username,
            "notes" => &mut self.entry.notes,
            "otp" if format > 1 => &mut self.entry.otp,
            _ => return None,
        };
        if slot.is_some() {
            return None;
        }
        let value = unescape(value)?;
        if key == "otp" && Otp::parse(&value).is_err() {
            return None;
        }
        *slot = Some(value);
        Some(())
    }

    fn finish(self, store: &mut Store) -> Result<(), Error> {
        let invalid = Error::Format { line: self.line };
        let modified = self.modified.ok_or(Error::Format { line: self.line })?;
        let entry = if self.deleted {
            None
        } else if self.entry.secret.is_none() && self.entry.otp.is_none() {
            return Err(invalid);
        } else {
            Some(self.entry)
        };
        let mut version = Version {
            modified,
            entry,
            history: self.history,
        };
        version.normalize();
        match store.versions.insert(self.name, version) {
            None => Ok(()),
            Some(_) => Err(invalid),
        }
    }
}

/// Reads a stamp: decimal milliseconds with no leading zeros, so each stamp
/// has one spelling.
fn parse_stamp(s: &str) -> Option<u64> {
    let canonical =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    canonical.then(|| s.parse().ok()).flatten()
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(match chars.next()? {
                '\\' => '\\',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                _ => return None,
            }),
            // escape() never leaves these raw.
            '\t' | '\r' => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Age(age::Error),
    /// Line numbers are safe to show; the line itself could hold a secret.
    Format {
        line: usize,
    },
    NotText,
    UnsupportedFormat(String),
    JsonFormat,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Age(e) => write!(f, "{e}"),
            Error::Format { line } => {
                write!(f, "line {line} of the decrypted store is not valid")
            }
            Error::NotText => write!(f, "the decrypted store is not UTF-8 text"),
            Error::UnsupportedFormat(v) => write!(
                f,
                "the store uses format {v}, but this multipass reads formats 1 to 3"
            ),
            Error::JsonFormat => write!(
                f,
                "the store is in the earlier JSON format, which this multipass cannot read; \
                 `age -d` on the store prints its entries so you can add them again"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// scrypt cost 2^10 keeps each test fast. The CLI always uses
    /// `age::DEFAULT_WORK_FACTOR`.
    const FAST: u8 = 10;

    /// Cutoffs that drop nothing.
    const KEEP_ALL: Cutoffs = Cutoffs {
        tombstones: 0,
        removed_secrets: 0,
        history: 0,
    };

    const OTP: &str = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
    const OTP_2: &str = "otpauth://totp/GitHub:octocat?secret=KRSXG5CTMVRXEZLU";

    fn secret(s: &str) -> Entry {
        Entry {
            secret: Some(s.into()),
            username: None,
            notes: None,
            otp: None,
        }
    }

    fn sample() -> Store {
        let mut store = Store::new();
        store.insert(
            "github.com",
            Entry {
                secret: Some("hunter1".into()),
                username: None,
                notes: None,
                otp: Some(OTP.into()),
            },
            1000,
        );
        store.insert(
            "github.com",
            Entry {
                secret: Some("hunter2".into()),
                username: None,
                notes: None,
                otp: Some(OTP.into()),
            },
            2000,
        );
        store.insert(
            "bank.example",
            Entry {
                secret: Some("correct horse battery staple".into()),
                username: Some("me@example.com".into()),
                notes: Some("recovery codes\nare in the safe".into()),
                otp: None,
            },
            3000,
        );
        store.insert(
            "aws-root",
            Entry {
                secret: None,
                username: None,
                notes: None,
                otp: Some("otpauth://totp/AWS?secret=KRSXG5CTMVRXEZLU&digits=8".into()),
            },
            4000,
        );
        store.insert("old-bank", secret("tr0ub4dor"), 5000);
        store.remove("old-bank", 6000);
        store
    }

    fn temp_dir() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "multipass-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn secrets(store: &Store, name: &str) -> Vec<(u64, String)> {
        let history = &store.version(name).unwrap().history;
        history
            .secrets
            .iter()
            .map(|p| (p.replaced, p.value.clone()))
            .collect()
    }

    #[test]
    fn writes_readable_text() {
        assert_eq!(
            sample().to_text(KEEP_ALL),
            "multipass 3\n\
             aws-root\n\
             \tmodified 4000\n\
             \totp otpauth://totp/AWS?secret=KRSXG5CTMVRXEZLU&digits=8\n\
             bank.example\n\
             \tmodified 3000\n\
             \tsecret correct horse battery staple\n\
             \tusername me@example.com\n\
             \tnotes recovery codes\\nare in the safe\n\
             github.com\n\
             \tmodified 2000\n\
             \tsecret hunter2\n\
             \totp otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n\
             \tprevious-secret 2000 hunter1\n\
             old-bank\n\
             \tmodified 6000\n\
             \tdeleted\n\
             \tprevious-secret 6000 tr0ub4dor\n"
        );
    }

    #[test]
    fn round_trips_awkward_characters() {
        let mut store = Store::new();
        for (i, s) in ["\\", "\n", "\t", "\r", " lead", "trail ", "\\n", "é ✓", ""]
            .iter()
            .enumerate()
        {
            let name = format!("name{s}{i}");
            let entry = |n: u32| Entry {
                secret: Some(format!("secret {n}{s}")),
                username: Some(s.to_string()),
                notes: Some(format!("{s}{s}")),
                otp: Some(format!(
                    "otpauth://totp/{n}{s}?secret=JBSWY3DPEHPK3PXP&x={s}"
                )),
            };
            store.insert(name.clone(), entry(1), 10);
            store.insert(name.clone(), entry(2), 20);
            if i % 2 == 0 {
                store.remove(&name, 30);
            }
        }
        assert_eq!(Store::from_text(&store.to_text(KEEP_ALL)).unwrap(), store);
    }

    #[test]
    fn round_trips_through_encryption() {
        let file = sample().encrypt("pass", FAST, KEEP_ALL).unwrap();
        assert_eq!(Store::decrypt("pass", &file).unwrap(), sample());
        assert!(matches!(
            Store::decrypt("wrong", &file),
            Err(Error::Age(age::Error::WrongPassphrase))
        ));
    }

    #[test]
    fn hides_names_and_secrets() {
        let file = sample().encrypt("pass", FAST, KEEP_ALL).unwrap();
        for needle in [
            "github.com",
            "hunter2",
            "hunter1",
            "tr0ub4dor",
            "bank.example",
            "JBSWY3DPEHPK3PXP",
        ] {
            assert!(
                !file.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "ciphertext contains {needle}"
            );
        }
    }

    #[test]
    fn rejects_malformed_text() {
        let cases = [
            ("", 1),
            ("multipass 1", 1),
            ("not multipass\n", 1),
            ("multipass 1\n\tsecret x\n", 2),
            ("multipass 1\nname\n", 2),
            ("multipass 1\nname\n\tsecret a\n\tsecret b\n", 4),
            ("multipass 1\nname\n\tpassword x\n", 3),
            ("multipass 1\nname\n\tsecretx\n", 3),
            ("multipass 1\nbad\\q\n\tsecret x\n", 2),
            ("multipass 1\n\n", 2),
            ("multipass 1\na\n\tsecret x\na\n\tsecret y\n", 4),
            ("multipass 2\nname\n\tusername u\n", 2),
            ("multipass 2\nname\n\totp otpauth://totp/x?secret=0\n", 3),
            ("multipass 2\nname\n\totp https://example.com\n", 3),
            (
                "multipass 1\nname\n\totp otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n",
                3,
            ),
            // Format 2 has neither stamps nor history.
            ("multipass 2\nname\n\tmodified 1\n\tsecret x\n", 3),
            ("multipass 2\nname\n\tsecret x\n\tprevious-secret 0 y\n", 4),
            ("multipass 2\nname\n\tdeleted\n", 3),
            // Format 3 needs `modified` first, in one spelling.
            ("multipass 3\nname\n\tsecret x\n", 3),
            ("multipass 3\nname\n", 2),
            ("multipass 3\nname\n\tsecret x\n\tmodified 1\n", 3),
            ("multipass 3\nname\n\tmodified 01\n\tsecret x\n", 3),
            ("multipass 3\nname\n\tmodified -1\n\tsecret x\n", 3),
            ("multipass 3\nname\n\tmodified \n\tsecret x\n", 3),
            ("multipass 3\nname\n\tmodified 1\n\tmodified 1\n", 4),
            ("multipass 3\nname\n\tmodified 1\n\tusername u\n", 2),
            // A tombstone holds no field.
            (
                "multipass 3\nname\n\tmodified 1\n\tdeleted\n\tsecret x\n",
                5,
            ),
            (
                "multipass 3\nname\n\tmodified 1\n\tsecret x\n\tdeleted\n",
                5,
            ),
            ("multipass 3\nname\n\tmodified 1\n\tdeleted\n\tdeleted\n", 5),
            ("multipass 3\nname\n\tmodified 1\n\tdeleted x\n", 4),
            // History needs a stamp no later than the entry's, and a value.
            (
                "multipass 3\nname\n\tmodified 5\n\tsecret x\n\tprevious-secret 6 y\n",
                5,
            ),
            (
                "multipass 3\nname\n\tmodified 5\n\tsecret x\n\tprevious-secret 5\n",
                5,
            ),
            (
                "multipass 3\nname\n\tmodified 5\n\tsecret x\n\tprevious-secret 5 \n",
                5,
            ),
            (
                "multipass 3\nname\n\tmodified 5\n\tsecret x\n\tprevious-secret x y\n",
                5,
            ),
            (
                "multipass 3\nname\n\tmodified 5\n\tsecret x\n\tprevious-otp 5 y\n",
                5,
            ),
            (
                "multipass 3\nname\n\tmodified 5\n\tsecret x\n\tprevious-notes 5 y\n",
                5,
            ),
        ];
        for (text, line) in cases {
            match Store::from_text(text) {
                Err(Error::Format { line: got }) => assert_eq!(got, line, "{text:?}"),
                other => panic!("{text:?} gave {other:?}"),
            }
        }
        assert!(matches!(
            Store::from_text("multipass 4\n"),
            Err(Error::UnsupportedFormat(v)) if v == "4"
        ));
        assert!(matches!(
            Store::from_text(r#"{"format":1,"entries":{"a":{"secret":"x"}}}"#),
            Err(Error::JsonFormat)
        ));
    }

    #[test]
    fn reads_formats_1_and_2_with_modified_0() {
        for text in [
            "multipass 1\nbank.example\n\tsecret s\n\tnotes n\n",
            "multipass 2\nbank.example\n\tsecret s\n\tnotes n\n",
        ] {
            let store = Store::from_text(text).unwrap();
            let version = store.version("bank.example").unwrap();
            assert_eq!(version.modified, 0, "{text:?}");
            let entry = version.entry.as_ref().unwrap();
            assert_eq!(
                (
                    entry.secret.as_deref(),
                    entry.notes.as_deref(),
                    entry.otp.as_deref()
                ),
                (Some("s"), Some("n"), None)
            );
            assert_eq!(
                store.to_text(KEEP_ALL),
                "multipass 3\nbank.example\n\tmodified 0\n\tsecret s\n\tnotes n\n"
            );
        }
    }

    #[test]
    fn reads_history_in_any_order_and_writes_it_newest_first() {
        let store = Store::from_text(
            "multipass 3\nx\n\tmodified 9\n\tsecret c\n\tprevious-secret 3 a\n\
             \tprevious-secret 7 b\n\tprevious-secret 5 a\n\tprevious-secret 8 c\n",
        )
        .unwrap();
        assert_eq!(
            store.to_text(KEEP_ALL),
            "multipass 3\nx\n\tmodified 9\n\tsecret c\n\tprevious-secret 7 b\n\tprevious-secret 5 a\n"
        );
    }

    #[test]
    fn rm_leaves_a_tombstone_that_hides_the_entry() {
        let mut store = sample();
        assert!(store.get("old-bank").is_none());
        assert!(store.names().all(|name| name != "old-bank"));
        assert_eq!(
            store.names().collect::<Vec<_>>(),
            ["aws-root", "bank.example", "github.com"]
        );
        assert_eq!(store.remove("old-bank", 7000), None);
        assert_eq!(store.remove("missing", 7000), None);
        assert!(store.version("missing").is_none());
    }

    #[test]
    fn replacing_keeps_the_old_secret_and_setup_key_as_history() {
        let mut store = Store::new();
        let with = |s: &str, otp: Option<&str>| Entry {
            secret: Some(s.into()),
            username: None,
            notes: None,
            otp: otp.map(String::from),
        };
        store.insert("x", with("a", Some(OTP)), 10);
        store.insert("x", with("b", Some(OTP)), 20);
        store.insert("x", with("b", Some(OTP_2)), 30);
        store.insert("x", with("a", Some(OTP_2)), 40);
        let history = &store.version("x").unwrap().history;
        // `a` is current again, so only `b` is earlier.
        assert_eq!(secrets(&store, "x"), [(40, "b".to_string())]);
        assert_eq!(
            history.otps,
            [Previous {
                replaced: 30,
                value: OTP.into()
            }]
        );
    }

    #[test]
    fn re_adding_a_removed_entry_keeps_its_history() {
        let mut store = Store::new();
        store.insert("x", secret("a"), 10);
        store.remove("x", 20);
        assert_eq!(secrets(&store, "x"), [(20, "a".to_string())]);
        store.insert("x", secret("b"), 30);
        assert_eq!(secrets(&store, "x"), [(20, "a".to_string())]);
    }

    /// A small generator, so the merge laws run over many stores without a
    /// dependency.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    fn generated(rng: &mut Rng) -> Store {
        let values = ["a", "b", "c"];
        let otps = [OTP, OTP_2];
        let mut store = Store::new();
        for name in ["x", "y", "z"] {
            if rng.below(4) == 0 {
                continue;
            }
            let modified = rng.below(4);
            let entry = (rng.below(3) != 0).then(|| Entry {
                secret: Some(values[rng.below(3) as usize].into()),
                username: (rng.below(2) == 0).then(|| "u".into()),
                notes: None,
                otp: (rng.below(2) == 0).then(|| otps[rng.below(2) as usize].into()),
            });
            let mut history = History::default();
            for _ in 0..rng.below(3) {
                history.secrets.push(Previous {
                    replaced: rng.below(modified + 1),
                    value: values[rng.below(3) as usize].into(),
                });
            }
            if rng.below(2) == 0 {
                history.otps.push(Previous {
                    replaced: rng.below(modified + 1),
                    value: otps[rng.below(2) as usize].into(),
                });
            }
            let mut version = Version {
                modified,
                entry,
                history,
            };
            version.normalize();
            store.versions.insert(name.into(), version);
        }
        store
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..3000 {
            let (a, b, c) = (
                generated(&mut rng),
                generated(&mut rng),
                generated(&mut rng),
            );
            let ab = Store::merge(&[a.clone(), b.clone()]);
            assert_eq!(ab, Store::merge(&[b.clone(), a.clone()]), "{a:?} {b:?}");
            assert_eq!(
                Store::merge(&[ab.clone(), c.clone()]),
                Store::merge(&[a.clone(), Store::merge(&[b.clone(), c.clone()])]),
                "{a:?} {b:?} {c:?}"
            );
            assert_eq!(Store::merge(&[a.clone(), a.clone()]), a);
            assert_eq!(Store::merge(std::slice::from_ref(&a)), a);
            assert_eq!(Store::merge(&[ab.clone(), a.clone()]), ab);
        }
    }

    #[test]
    fn merge_keeps_changes_to_different_entries() {
        let mut base = Store::new();
        base.insert("w", secret("w"), 10);
        let (mut one, mut two) = (base.clone(), base.clone());
        one.insert("x", secret("x"), one.stamp(20));
        two.insert("y", secret("y"), two.stamp(20));
        let merged = Store::merge(&[one, two]);
        assert_eq!(merged.names().collect::<Vec<_>>(), ["w", "x", "y"]);
    }

    #[test]
    fn the_losing_edit_becomes_history() {
        let mut base = Store::new();
        base.insert("x", secret("old"), 10);
        let (mut one, mut two) = (base.clone(), base.clone());
        one.insert("x", secret("from one"), 20);
        two.insert("x", secret("from two"), 30);
        for merged in [
            Store::merge(&[one.clone(), two.clone()]),
            Store::merge(&[two.clone(), one.clone()]),
        ] {
            assert_eq!(merged.get("x"), Some(&secret("from two")));
            assert_eq!(
                secrets(&merged, "x"),
                [(30, "old".to_string()), (20, "from one".to_string())]
            );
        }
    }

    #[test]
    fn edit_against_removal_keeps_the_later_stamp() {
        let mut base = Store::new();
        base.insert("x", secret("old"), 10);
        for (edit_at, remove_at, survives) in [(30, 20, true), (20, 30, false)] {
            let (mut edited, mut removed) = (base.clone(), base.clone());
            edited.insert("x", secret("new"), edit_at);
            removed.remove("x", remove_at);
            for merged in [
                Store::merge(&[edited.clone(), removed.clone()]),
                Store::merge(&[removed.clone(), edited.clone()]),
            ] {
                assert_eq!(merged.get("x").is_some(), survives, "{merged:?}");
                // Whichever wins, neither secret is lost.
                let kept = secrets(&merged, "x");
                assert!(kept.iter().any(|(_, v)| v == "old"), "{merged:?}");
                assert_eq!(kept.iter().any(|(_, v)| v == "new"), !survives);
            }
        }
    }

    #[test]
    fn a_tie_is_broken_by_content() {
        let mut one = Store::new();
        let mut two = Store::new();
        one.insert("x", secret("a"), 10);
        two.insert("x", secret("b"), 10);
        let merged = Store::merge(&[one.clone(), two.clone()]);
        assert_eq!(merged, Store::merge(&[two, one]));
        assert_eq!(merged.get("x"), Some(&secret("b")));
        assert_eq!(secrets(&merged, "x"), [(10, "a".to_string())]);
    }

    #[test]
    fn stamps_pass_the_newest_change() {
        let now = 1_764_160_000_000;
        let hour = 60 * 60 * 1000;
        assert_eq!(Store::new().stamp(now), now);

        let mut store = Store::new();
        store.insert("x", secret("a"), now - hour);
        assert_eq!(store.stamp(now), now);

        store.remove("x", now + hour);
        assert_eq!(store.stamp(now), now + hour + 1);
        assert!(!dated_in_future(store.stamp(now), now));

        store.insert("x", secret("b"), now + DAY + 60_000);
        assert_eq!(store.stamp(now), now + DAY + 60_001);
        assert!(dated_in_future(store.stamp(now), now));
    }

    #[test]
    fn drops_old_tombstones_at_the_cutoff() {
        let now = 400 * DAY;
        let cutoff = Cutoffs::at(now).tombstones;
        assert_eq!(cutoff, now - 120 * DAY);
        let text = |removed_at: u64, cutoffs: Cutoffs| {
            let mut store = Store::new();
            store.insert("x", secret("a"), 1);
            store.remove("x", removed_at);
            store.to_text(cutoffs)
        };
        assert_eq!(text(cutoff - 1, Cutoffs::at(now)), "multipass 3\n");
        assert_eq!(
            text(cutoff, Cutoffs::at(now)),
            format!("multipass 3\nx\n\tmodified {cutoff}\n\tdeleted\n")
        );
        // An old key the vault-key plan still holds moves the cutoff back.
        let old_key = Cutoffs {
            tombstones: now - 250 * DAY,
            ..Cutoffs::at(now)
        };
        assert!(text(now - 200 * DAY, old_key).contains("\tdeleted\n"));
    }

    #[test]
    fn a_removed_entry_keeps_its_secrets_for_30_days() {
        let now = 400 * DAY;
        let cutoff = Cutoffs::at(now).removed_secrets;
        assert_eq!(cutoff, now - 30 * DAY);
        let store = |removed_at: u64| {
            let mut store = Store::new();
            store.insert("x", secret("a"), 1);
            store.remove("x", removed_at);
            Store::from_text(&store.to_text(Cutoffs::at(now))).unwrap()
        };
        assert_eq!(secrets(&store(cutoff), "x"), [(cutoff, "a".to_string())]);
        let expired = store(cutoff - 1);
        assert!(secrets(&expired, "x").is_empty());
        assert!(expired.version("x").unwrap().entry.is_none());
    }

    #[test]
    fn keeps_ten_earlier_values_or_a_year_of_them() {
        let now = 1000 * DAY;
        let year_ago = Cutoffs::at(now).history;
        assert_eq!(year_ago, now - 365 * DAY);
        // Each value is replaced by the next insert, so value `i` is dated by
        // the time of insert `i + 1`.
        let kept = |inserted: &[u64]| {
            let mut store = Store::new();
            for (i, at) in inserted.iter().enumerate() {
                store.insert("x", secret(&i.to_string()), *at);
            }
            store.insert("x", secret("current"), now);
            let read = Store::from_text(&store.to_text(Cutoffs::at(now))).unwrap();
            secrets(&read, "x").len()
        };
        // Twelve values replaced long ago: the newest ten stay.
        let old: Vec<u64> = (1..=12).collect();
        assert_eq!(kept(&old), 10);
        // Twelve values, all but the oldest replaced within the year: eleven
        // stay, and the oldest stays too when it was replaced at the cutoff.
        let with_oldest_replaced_at = |t: u64| {
            let mut inserted = vec![1, t];
            inserted.extend((0..10).map(|i| now - 20 + i));
            kept(&inserted)
        };
        assert_eq!(with_oldest_replaced_at(year_ago - 1), 11);
        assert_eq!(with_oldest_replaced_at(year_ago), 12);
    }

    #[test]
    fn saves_atomically_with_private_permissions() {
        let dir = temp_dir();
        let path = dir.join("nested").join("store.age");

        sample().save(&path, "pass", FAST, KEEP_ALL).unwrap();
        assert_eq!(Store::load(&path, "pass").unwrap(), sample());
        assert!(!path.with_extension("age.tmp").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
