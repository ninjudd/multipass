//! The encrypted store: a map from entry name to [`Entry`], serialized as JSON
//! and encrypted with an age passphrase.
//!
//! The file is a standard age file, so it can always be recovered without
//! multipass: `age -d ~/.multipass/store.age` prints the JSON.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// The version of the JSON document inside the age file. Bump it when the
/// shape changes, and teach [`Store::decrypt`] to read the old one.
pub const FORMAT: u32 = 1;

/// One secret and what goes with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl Entry {
    #[cfg(test)]
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            username: None,
            notes: None,
        }
    }
}

/// Every entry, keyed by name. Names live inside the encrypted file, so the
/// file on disk does not reveal which accounts it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Store {
    format: u32,
    entries: BTreeMap<String, Entry>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Self {
            format: FORMAT,
            entries: BTreeMap::new(),
        }
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

    /// Encrypts the store with `passphrase`.
    ///
    /// `work_factor` sets scrypt's cost to `2^work_factor`. Leave it `None` to
    /// let age pick a cost that takes about a second on this machine; tests
    /// pass a small value to stay fast.
    pub fn encrypt(
        &self,
        passphrase: &SecretString,
        work_factor: Option<u8>,
    ) -> Result<Vec<u8>, Error> {
        let plaintext = serde_json::to_vec(self).map_err(|_| Error::Format)?;
        let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
        if let Some(log_n) = work_factor {
            recipient.set_work_factor(log_n);
        }
        age::encrypt(&recipient, &plaintext).map_err(Error::Encrypt)
    }

    /// Decrypts a store produced by [`Store::encrypt`] or by `age -p`.
    pub fn decrypt(passphrase: &SecretString, ciphertext: &[u8]) -> Result<Self, Error> {
        let identity = age::scrypt::Identity::new(passphrase.clone());
        let plaintext = age::decrypt(&identity, ciphertext).map_err(Error::Decrypt)?;
        let store: Store = serde_json::from_slice(&plaintext).map_err(|_| Error::Format)?;
        if store.format != FORMAT {
            return Err(Error::UnsupportedFormat(store.format));
        }
        Ok(store)
    }

    pub fn load(path: &Path, passphrase: &SecretString) -> Result<Self, Error> {
        let ciphertext = fs::read(path).map_err(Error::Io)?;
        Self::decrypt(passphrase, &ciphertext)
    }

    /// Encrypts the store and replaces the file at `path` atomically: the new
    /// ciphertext goes to a temporary file beside it, which is then renamed
    /// over the old one, so a crash never leaves a half-written store.
    pub fn save(
        &self,
        path: &Path,
        passphrase: &SecretString,
        work_factor: Option<u8>,
    ) -> Result<(), Error> {
        let ciphertext = self.encrypt(passphrase, work_factor)?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            create_private_dir(dir).map_err(Error::Io)?;
        }
        let tmp = path.with_extension("age.tmp");
        let result = write_private(&tmp, &ciphertext).and_then(|()| fs::rename(&tmp, path));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(Error::Io)
    }
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
    Encrypt(age::EncryptError),
    Decrypt(age::DecryptError),
    /// Carries no detail: serde_json's message could quote decrypted plaintext.
    Format,
    UnsupportedFormat(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Encrypt(e) => write!(f, "encryption failed: {e}"),
            Error::Decrypt(
                age::DecryptError::DecryptionFailed
                | age::DecryptError::KeyDecryptionFailed
                | age::DecryptError::NoMatchingKeys,
            ) => write!(f, "wrong passphrase, or the store is damaged"),
            Error::Decrypt(e) => write!(f, "decryption failed: {e}"),
            Error::Format => write!(f, "the decrypted store is not valid multipass JSON"),
            Error::UnsupportedFormat(v) => write!(
                f,
                "the store uses format {v}, but this multipass reads format {FORMAT}"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    /// scrypt cost 2^10 keeps each test well under a second. The CLI never
    /// passes a work factor, so real stores use age's default of about a second.
    const FAST: Option<u8> = Some(10);

    fn passphrase(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn sample() -> Store {
        let mut store = Store::new();
        store.insert("github.com", Entry::new("hunter2"));
        store.insert(
            "bank.example",
            Entry {
                secret: "correct horse battery staple".into(),
                username: Some("me@example.com".into()),
                notes: Some("recovery codes in the safe".into()),
            },
        );
        store
    }

    #[test]
    fn round_trips_through_encryption() {
        let store = sample();
        let ciphertext = store.encrypt(&passphrase("pass"), FAST).unwrap();
        let decrypted = Store::decrypt(&passphrase("pass"), &ciphertext).unwrap();
        assert_eq!(decrypted, store);
        assert_eq!(
            decrypted.names().collect::<Vec<_>>(),
            ["bank.example", "github.com"]
        );
    }

    #[test]
    fn rejects_the_wrong_passphrase() {
        let ciphertext = sample().encrypt(&passphrase("right"), FAST).unwrap();
        let err = Store::decrypt(&passphrase("wrong"), &ciphertext).unwrap_err();
        assert_eq!(err.to_string(), "wrong passphrase, or the store is damaged");
    }

    #[test]
    fn writes_a_standard_age_file() {
        // The header is what `age -d` and `rage -d` recognize, so the store can be
        // recovered without multipass.
        let ciphertext = sample().encrypt(&passphrase("pass"), FAST).unwrap();
        assert!(ciphertext.starts_with(b"age-encryption.org/v1\n-> scrypt "));
    }

    #[test]
    fn hides_names_and_secrets() {
        let ciphertext = sample().encrypt(&passphrase("pass"), FAST).unwrap();
        for needle in ["github.com", "hunter2", "bank.example", "me@example.com"] {
            assert!(
                !ciphertext
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes()),
                "ciphertext contains {needle}"
            );
        }
    }

    #[test]
    fn rejects_an_unknown_format() {
        // A file made by plain `age -p` from JSON with a newer format number.
        let json = br#"{"format":99,"entries":{}}"#;
        let mut recipient = age::scrypt::Recipient::new(passphrase("pass"));
        recipient.set_work_factor(10);
        let ciphertext = age::encrypt(&recipient, json).unwrap();
        let err = Store::decrypt(&passphrase("pass"), &ciphertext).unwrap_err();
        assert!(matches!(err, Error::UnsupportedFormat(99)));
    }

    #[test]
    fn saves_atomically_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("store.age");

        sample().save(&path, &passphrase("pass"), FAST).unwrap();
        let loaded = Store::load(&path, &passphrase("pass")).unwrap();
        assert_eq!(loaded, sample());
        assert!(!path.with_extension("age.tmp").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(file_mode & 0o777, 0o600);
            assert_eq!(dir_mode & 0o777, 0o700);
        }
    }
}
