//! The store: every entry, kept as a small text document inside one age file.
//!
//! The text is meant to be read by a person recovering the store with plain
//! `age -d`:
//!
//! ```text
//! multipass 1
//! github.com
//!     secret hunter2
//!     username octocat
//! bank.example
//!     secret correct horse battery staple
//!     notes recovery codes\nare in the safe
//! ```
//!
//! An unindented line names an entry. Each line under it is indented with
//! one tab (shown as spaces above) and holds a field name, one space, and the
//! value. Names and values escape backslash, newline, tab and carriage return
//! as `\\`, `\n`, `\t` and `\r`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::age;

const HEADER: &str = "multipass 1";

/// One secret and what goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub secret: String,
    pub username: Option<String>,
    pub notes: Option<String>,
}

/// Every entry, keyed by name. Names live inside the encrypted file, so the
/// file on disk does not reveal which accounts it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Store {
    entries: BTreeMap<String, Entry>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }

    /// Adds or replaces an entry, returning the one it replaced.
    pub fn insert(&mut self, name: impl Into<String>, entry: Entry) -> Option<Entry> {
        self.entries.insert(name.into(), entry)
    }

    pub fn remove(&mut self, name: &str) -> Option<Entry> {
        self.entries.remove(name)
    }

    /// Entry names in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn to_text(&self) -> String {
        let mut out = format!("{HEADER}\n");
        for (name, entry) in &self.entries {
            out.push_str(&escape(name));
            out.push('\n');
            let fields = [
                ("secret", Some(&entry.secret)),
                ("username", entry.username.as_ref()),
                ("notes", entry.notes.as_ref()),
            ];
            for (field, value) in fields {
                if let Some(value) = value {
                    out.push_str(&format!("\t{field} {}\n", escape(value)));
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

        match lines.next() {
            Some((HEADER, _)) => {}
            Some((first, _)) if first.starts_with("multipass ") => {
                return Err(Error::UnsupportedFormat(first["multipass ".len()..].into()));
            }
            _ => return Err(Error::Format { line: 1 }),
        }

        let mut store = Store::new();
        let mut pending: Option<Pending> = None;
        for (line, n) in lines {
            if let Some(field) = line.strip_prefix('\t') {
                let entry = pending.as_mut().ok_or(Error::Format { line: n })?;
                let (key, value) = field.split_once(' ').ok_or(Error::Format { line: n })?;
                let slot = match key {
                    "secret" => &mut entry.secret,
                    "username" => &mut entry.username,
                    "notes" => &mut entry.notes,
                    _ => return Err(Error::Format { line: n }),
                };
                if slot.is_some() {
                    return Err(Error::Format { line: n });
                }
                *slot = Some(unescape(value).ok_or(Error::Format { line: n })?);
            } else {
                if let Some(done) = pending.take() {
                    done.finish(&mut store)?;
                }
                let name = unescape(line)
                    .filter(|name| !name.is_empty())
                    .ok_or(Error::Format { line: n })?;
                pending = Some(Pending {
                    line: n,
                    name,
                    secret: None,
                    username: None,
                    notes: None,
                });
            }
        }
        if let Some(done) = pending {
            done.finish(&mut store)?;
        }
        Ok(store)
    }

    /// Encrypts the store with `passphrase` at scrypt cost `2^work_factor`.
    pub fn encrypt(&self, passphrase: &str, work_factor: u8) -> Result<Vec<u8>, Error> {
        age::encrypt(
            passphrase.as_bytes(),
            self.to_text().as_bytes(),
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
    pub fn save(&self, path: &Path, passphrase: &str, work_factor: u8) -> Result<(), Error> {
        let file = self.encrypt(passphrase, work_factor)?;
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

struct Pending {
    line: usize,
    name: String,
    secret: Option<String>,
    username: Option<String>,
    notes: Option<String>,
}

impl Pending {
    fn finish(self, store: &mut Store) -> Result<(), Error> {
        let secret = self.secret.ok_or(Error::Format { line: self.line })?;
        let entry = Entry {
            secret,
            username: self.username,
            notes: self.notes,
        };
        match store.insert(self.name, entry) {
            None => Ok(()),
            Some(_) => Err(Error::Format { line: self.line }),
        }
    }
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
                "the store uses format {v}, but this multipass reads format 1"
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

    fn sample() -> Store {
        let mut store = Store::new();
        store.insert(
            "github.com",
            Entry {
                secret: "hunter2".into(),
                username: None,
                notes: None,
            },
        );
        store.insert(
            "bank.example",
            Entry {
                secret: "correct horse battery staple".into(),
                username: Some("me@example.com".into()),
                notes: Some("recovery codes\nare in the safe".into()),
            },
        );
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

    #[test]
    fn writes_readable_text() {
        assert_eq!(
            sample().to_text(),
            "multipass 1\n\
             bank.example\n\
             \tsecret correct horse battery staple\n\
             \tusername me@example.com\n\
             \tnotes recovery codes\\nare in the safe\n\
             github.com\n\
             \tsecret hunter2\n"
        );
    }

    #[test]
    fn round_trips_awkward_characters() {
        let mut store = Store::new();
        for (i, s) in ["\\", "\n", "\t", "\r", " lead", "trail ", "\\n", "é ✓", ""]
            .iter()
            .enumerate()
        {
            store.insert(
                format!("name{s}{i}"),
                Entry {
                    secret: format!("secret{s}"),
                    username: Some(s.to_string()),
                    notes: Some(format!("{s}{s}")),
                },
            );
        }
        assert_eq!(Store::from_text(&store.to_text()).unwrap(), store);
    }

    #[test]
    fn round_trips_through_encryption() {
        let file = sample().encrypt("pass", FAST).unwrap();
        assert_eq!(Store::decrypt("pass", &file).unwrap(), sample());
        assert!(matches!(
            Store::decrypt("wrong", &file),
            Err(Error::Age(age::Error::WrongPassphrase))
        ));
    }

    #[test]
    fn hides_names_and_secrets() {
        let file = sample().encrypt("pass", FAST).unwrap();
        for needle in ["github.com", "hunter2", "bank.example", "me@example.com"] {
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
        ];
        for (text, line) in cases {
            match Store::from_text(text) {
                Err(Error::Format { line: got }) => assert_eq!(got, line, "{text:?}"),
                other => panic!("{text:?} gave {other:?}"),
            }
        }
        assert!(matches!(
            Store::from_text("multipass 2\n"),
            Err(Error::UnsupportedFormat(v)) if v == "2"
        ));
        assert!(matches!(
            Store::from_text(r#"{"format":1,"entries":{"a":{"secret":"x"}}}"#),
            Err(Error::JsonFormat)
        ));
    }

    #[test]
    fn saves_atomically_with_private_permissions() {
        let dir = temp_dir();
        let path = dir.join("nested").join("store.age");

        sample().save(&path, "pass", FAST).unwrap();
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
