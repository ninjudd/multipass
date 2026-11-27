//! The store package: a directory of age files that multipass writes once
//! and never modifies.
//!
//! ```text
//! store.multipass/
//!     key.<gen>.age            the vault key, under your passphrase
//!     store.<gen>.<id>.age     a whole store, under generation <gen>'s key
//! ```
//!
//! The passphrase unlocks a key file, which holds a random vault key, the
//! time it was made, and the keys it replaced in the last 90 days. The vault
//! key's text is the passphrase of every store file of its generation. Every
//! save writes a new store file holding the merged store and then deletes
//! the files it read, so a file another Mac writes meanwhile is never
//! touched, and the next open merges it. A key is replaced when a prompt
//! finds it 14 or more days old, on every `passwd`, and on `rekey`.
//!
//! Keys stay text here, as secrets do in `src/store.rs`: this module reads
//! and writes the key file's lines, and every computation on key material
//! happens in `src/crypto` and `src/age.rs`.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::age;
use crate::crypto::random;
use crate::store::{self, Cutoffs, Store};

const KEY_HEADER: &str = "multipass-key 1";

/// A day in seconds, the unit of the key file's times.
const DAY: u64 = 24 * 60 * 60;

/// A prompt rotates the vault key once it is this old.
const ROTATE_AFTER_DAYS: u64 = 14;

/// A replaced key stays in the key file this long, so a store file that
/// another Mac wrote under it before hearing of the rotation still opens.
const RETIRED_DAYS: u64 = 90;

/// How many times `open` lists the package again when a file it was reading
/// disappears, because another Mac merged and deleted it.
const ATTEMPTS: usize = 3;

/// A vault key and its generation. Its `Debug` output leaves out the key.
#[derive(Clone, PartialEq, Eq)]
struct Key {
    generation: String,
    /// When the key was made, in Unix seconds.
    created: u64,
    /// The key's base64 text, which is the passphrase of its store files.
    text: String,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("generation", &self.generation)
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

/// A key that a rotation replaced, and when, in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Retired {
    key: Key,
    retired: u64,
}

/// The text of a key file, `key.<gen>.age`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyFile {
    key: Key,
    /// When the passphrase that encrypts this file was set, in Unix
    /// seconds, so two lineages under two passphrases can tell which is
    /// newer.
    passphrase_set: u64,
    retired: Vec<Retired>,
}

impl KeyFile {
    fn to_text(&self) -> String {
        let mut out = format!(
            "{KEY_HEADER}\ngeneration {}\ncreated {}\npassphrase-set {}\nkey {}\n",
            self.key.generation, self.key.created, self.passphrase_set, self.key.text
        );
        for r in &self.retired {
            out.push_str(&format!(
                "retired {} {} {} {}\n",
                r.key.generation, r.key.created, r.retired, r.key.text
            ));
        }
        out
    }

    /// Reads a key file's text. An error names nothing from the text,
    /// which holds keys.
    fn from_text(text: &str) -> Option<KeyFile> {
        let mut lines = text.lines();
        if lines.next()? != KEY_HEADER {
            return None;
        }
        let mut field = |name: &str| {
            lines
                .next()?
                .strip_prefix(name)?
                .strip_prefix(' ')
                .map(str::to_string)
        };
        let generation = field("generation").filter(|g| is_id(g))?;
        let created = parse_time(&field("created")?)?;
        let passphrase_set = parse_time(&field("passphrase-set")?)?;
        let text_of_key = field("key")?;
        let mut retired = Vec::new();
        for line in lines {
            let mut parts = line.strip_prefix("retired ")?.split(' ');
            let generation = parts.next().filter(|g| is_id(g))?.to_string();
            let created = parse_time(parts.next()?)?;
            let retired_at = parse_time(parts.next()?)?;
            let text = parts.next()?.to_string();
            if parts.next().is_some() {
                return None;
            }
            retired.push(Retired {
                key: Key {
                    generation,
                    created,
                    text,
                },
                retired: retired_at,
            });
        }
        Some(KeyFile {
            key: Key {
                generation,
                created,
                text: text_of_key,
            },
            passphrase_set,
            retired,
        })
    }
}

fn parse_time(s: &str) -> Option<u64> {
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| s.parse().ok())?
}

/// True for 32 lower-case hex digits, the shape of every generation and id.
fn is_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A file in the package, by kind.
#[derive(Debug, Clone)]
struct Listed {
    generation: String,
    path: PathBuf,
}

#[derive(Debug, Default)]
struct Listing {
    keys: Vec<Listed>,
    stores: Vec<Listed>,
    /// Names that match no kind, which `open` warns about and leaves alone.
    foreign: Vec<String>,
}

/// What `open` asks for.
pub enum Ask<'a> {
    /// The passphrase.
    Passphrase,
    /// Another passphrase, for these key files, which the first one does not
    /// open. `None` opens the store read-only.
    Other(&'a [String]),
}

/// What `settle` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    Nothing,
    Compacted,
    Rotated,
}

/// A store package on disk.
pub struct Vault {
    dir: PathBuf,
    /// The scrypt work factor for key files: `age::DEFAULT_WORK_FACTOR` in
    /// the CLI, and lower in tests.
    key_work_factor: u8,
    /// Durable writes and removals done so far, and, in tests, the count at
    /// which to stop, to simulate a crash.
    steps: Cell<usize>,
    #[cfg(test)]
    stop_after: Option<usize>,
}

/// An open store: the merged store, and the keys and files that a save or
/// a rotation needs. Its fields hold keys, so it has no `Debug`.
pub struct Session {
    pub store: Store,
    current: Key,
    /// Every key that can open a store file, by generation, with when it
    /// was retired, or `None` for the current key of a key file that opened.
    known: BTreeMap<String, (Key, Option<u64>)>,
    key_files: Vec<PathBuf>,
    store_files: Vec<PathBuf>,
    /// The passphrase a new key file is written under, and when it was set.
    /// `None` when some key file did not open, so nothing may be written.
    passphrase: Option<(String, u64)>,
    /// What `open` saw that you should know, such as files it left alone.
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NoStore(PathBuf),
    Exists(PathBuf),
    WrongPassphrase,
    StillSyncing,
    ReadOnly,
    /// A file named here did not parse or authenticate. The name is public.
    Damaged(String),
    /// A test's simulated crash.
    #[cfg(test)]
    Stopped,
    /// A file disappeared while `open` read it; `open` lists again.
    Vanished,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NoStore(path) => write!(
                f,
                "no store at {}; run multipass init to create one",
                path.display()
            ),
            Error::Exists(path) => write!(f, "a store already exists at {}", path.display()),
            Error::WrongPassphrase => write!(f, "wrong passphrase, or the store is damaged"),
            Error::StillSyncing => write!(f, "the store is still syncing; try again shortly"),
            Error::ReadOnly => write!(
                f,
                "another passphrase was set on another Mac; type it to save"
            ),
            Error::Damaged(name) => write!(f, "{name} is damaged or has been tampered with"),
            #[cfg(test)]
            Error::Stopped => write!(f, "stopped"),
            Error::Vanished => write!(f, "the store changed while it was being read"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            Error::Vanished
        } else {
            Error::Io(e)
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

fn seconds(now_ms: u64) -> u64 {
    now_ms / 1000
}

impl Vault {
    pub fn new(dir: impl Into<PathBuf>, key_work_factor: u8) -> Self {
        Vault {
            dir: dir.into(),
            key_work_factor,
            steps: Cell::new(0),
            #[cfg(test)]
            stop_after: None,
        }
    }

    /// The package's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Counts one durable write or removal, and in a test stops before it
    /// once `stop_after` is reached.
    fn step(&self) -> Result<()> {
        let done = self.steps.get();
        #[cfg(test)]
        if self.stop_after == Some(done) {
            return Err(Error::Stopped);
        }
        self.steps.set(done + 1);
        Ok(())
    }

    fn write(&self, dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
        self.step()?;
        store::write_private_durable(dir, name, bytes).map_err(Error::Io)
    }

    fn remove(&self, path: &Path) -> Result<()> {
        self.step()?;
        store::remove_durable(path).map_err(Error::Io)
    }

    /// Creates a package holding a new key under `passphrase` and an empty
    /// store. It builds the package in `<name>.tmp` beside it and renames it
    /// into place, so the package appears whole or not at all.
    pub fn init(&self, passphrase: &str, now_ms: u64) -> Result<()> {
        if self.dir.exists() {
            return Err(Error::Exists(self.dir.clone()));
        }
        let tmp = self.tmp_dir();
        if tmp.exists() {
            fs::remove_dir_all(&tmp).map_err(Error::Io)?;
        }
        store::create_private_dir(&tmp).map_err(Error::Io)?;
        let key = new_key(seconds(now_ms))?;
        let file = KeyFile {
            key: key.clone(),
            passphrase_set: seconds(now_ms),
            retired: Vec::new(),
        };
        self.write_key_file(&tmp, &file, passphrase)?;
        self.write_store_file(&tmp, &key, &Store::new(), Cutoffs::at(now_ms))?;
        self.step()?;
        fs::rename(&tmp, &self.dir).map_err(Error::Io)?;
        if let Some(parent) = self.dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            store::sync_dir(parent).map_err(Error::Io)?;
        }
        Ok(())
    }

    fn tmp_dir(&self) -> PathBuf {
        let mut name = self.dir.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        self.dir.with_file_name(name)
    }

    fn write_key_file(&self, dir: &Path, file: &KeyFile, passphrase: &str) -> Result<()> {
        let bytes = age::encrypt(
            passphrase.as_bytes(),
            file.to_text().as_bytes(),
            self.key_work_factor,
        )
        .map_err(Error::Io)?;
        self.write(dir, &format!("key.{}.age", file.key.generation), &bytes)
    }

    /// Writes `store` as a new store file under `key`, returning its path.
    fn write_store_file(
        &self,
        dir: &Path,
        key: &Key,
        store: &Store,
        cutoffs: Cutoffs,
    ) -> Result<PathBuf> {
        let bytes = store
            .encrypt(&key.text, age::VAULT_WORK_FACTOR, cutoffs)
            .map_err(|e| match e {
                store::Error::Io(e) => Error::Io(e),
                _ => Error::Damaged("the new store file".into()),
            })?;
        let name = format!("store.{}.{}.age", key.generation, random::id()?);
        self.write(dir, &name, &bytes)?;
        Ok(dir.join(name))
    }

    fn list(&self) -> Result<Listing> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::NoStore(self.dir.clone()));
            }
            Err(e) => return Err(Error::Io(e)),
        };
        let mut listing = Listing::default();
        for entry in entries {
            let entry = entry.map_err(Error::Io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') && (name.ends_with(".tmp") || name == ".DS_Store") {
                continue;
            }
            let path = entry.path();
            let parts: Vec<&str> = name.split('.').collect();
            match parts.as_slice() {
                ["key", generation, "age"] if is_id(generation) => listing.keys.push(Listed {
                    generation: generation.to_string(),
                    path,
                }),
                ["store", generation, id, "age"] if is_id(generation) && is_id(id) => {
                    listing.stores.push(Listed {
                        generation: generation.to_string(),
                        path,
                    })
                }
                _ => listing.foreign.push(name),
            }
        }
        listing.keys.sort_by(|a, b| a.path.cmp(&b.path));
        listing.stores.sort_by(|a, b| a.path.cmp(&b.path));
        listing.foreign.sort();
        Ok(listing)
    }

    /// Opens the package: asks for the passphrase, decrypts every key file
    /// it opens, and merges every store file it has a key for. It changes
    /// nothing on disk; `Session::settle` rotates or compacts afterwards.
    pub fn open(
        &self,
        ask: &mut dyn FnMut(Ask) -> io::Result<Option<String>>,
        now_ms: u64,
    ) -> Result<Session> {
        let listing = self.list()?;
        if listing.keys.is_empty() {
            return Err(if listing.stores.is_empty() {
                Error::NoStore(self.dir.clone())
            } else {
                Error::StillSyncing
            });
        }
        let passphrase = ask(Ask::Passphrase)
            .map_err(Error::Io)?
            .ok_or(Error::WrongPassphrase)?;
        // Ask for another passphrase at most once, however often the
        // package is listed again.
        let mut other: Option<Option<String>> = None;
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.try_open(&passphrase, &mut other, ask, now_ms) {
                Err(Error::Vanished) if attempt < ATTEMPTS => continue,
                result => return result,
            }
        }
    }

    fn try_open(
        &self,
        passphrase: &str,
        other: &mut Option<Option<String>>,
        ask: &mut dyn FnMut(Ask) -> io::Result<Option<String>>,
        now_ms: u64,
    ) -> Result<Session> {
        let listing = self.list()?;
        let mut warnings: Vec<String> = listing
            .foreign
            .iter()
            .map(|name| format!("left {name} alone in the store package: not a store file"))
            .collect();

        let mut opened: Vec<(PathBuf, KeyFile, bool)> = Vec::new();
        let mut unopened: Vec<&Listed> = Vec::new();
        for listed in &listing.keys {
            match read_key_file(&listed.path, passphrase)? {
                Some(file) => opened.push((listed.path.clone(), file, false)),
                None => unopened.push(listed),
            }
        }
        if opened.is_empty() {
            return Err(Error::WrongPassphrase);
        }
        if !unopened.is_empty() {
            if other.is_none() {
                let names: Vec<String> = unopened.iter().map(|l| file_name(&l.path)).collect();
                *other = Some(ask(Ask::Other(&names)).map_err(Error::Io)?);
            }
            if let Some(Some(second)) = other.as_ref() {
                let mut still = Vec::new();
                for listed in unopened {
                    match read_key_file(&listed.path, second)? {
                        Some(file) => opened.push((listed.path.clone(), file, true)),
                        None => still.push(listed),
                    }
                }
                unopened = still;
            }
        }

        // Write under the passphrase whose key files carry the later
        // `passphrase-set`, so a `passwd` wins over a rotation that raced it.
        let newest_set = |second: bool| {
            opened
                .iter()
                .filter(|(_, _, s)| *s == second)
                .map(|(_, f, _)| f.passphrase_set)
                .max()
        };
        let writer = match (newest_set(false), newest_set(true), other.as_ref()) {
            (Some(first), Some(second_set), Some(Some(second))) if second_set > first => {
                (second.clone(), second_set)
            }
            (Some(first), _, _) => (passphrase.to_string(), first),
            _ => unreachable!("a key file opened with the first passphrase"),
        };
        let passphrase = unopened.is_empty().then_some(writer);

        let now = seconds(now_ms);
        let mut known: BTreeMap<String, (Key, Option<u64>)> = BTreeMap::new();
        for (_, file, _) in &opened {
            for r in &file.retired {
                if r.retired + RETIRED_DAYS * DAY < now {
                    continue;
                }
                let latest = match known.get(&r.key.generation) {
                    Some((_, Some(at))) => (*at).max(r.retired),
                    _ => r.retired,
                };
                known.insert(r.key.generation.clone(), (r.key.clone(), Some(latest)));
            }
        }
        for (_, file, _) in &opened {
            known
                .entry(file.key.generation.clone())
                .or_insert_with(|| (file.key.clone(), None));
        }
        let current = opened
            .iter()
            .map(|(_, f, _)| &f.key)
            .max_by(|a, b| (a.created, &a.generation).cmp(&(b.created, &b.generation)))
            .expect("a key file opened")
            .clone();

        let mut stores = Vec::new();
        let mut store_files = Vec::new();
        for listed in &listing.stores {
            let Some((key, _)) = known.get(&listed.generation) else {
                warnings.push(format!(
                    "left {} alone: no key this passphrase opens is of its generation",
                    file_name(&listed.path)
                ));
                continue;
            };
            let bytes = fs::read(&listed.path)?;
            let mut store = Store::decrypt(&key.text, &bytes)
                .map_err(|_| Error::Damaged(file_name(&listed.path)))?;
            // Expire before merging, as a save would, so history a file
            // still holds past its cutoff cannot join a live entry's.
            store.expire(cutoffs(&known, now_ms));
            stores.push(store);
            store_files.push(listed.path.clone());
        }
        if stores.is_empty() {
            return Err(Error::StillSyncing);
        }

        Ok(Session {
            store: {
                let mut merged = Store::merge(&stores);
                merged.expire(cutoffs(&known, now_ms));
                merged
            },
            current,
            known,
            key_files: opened.into_iter().map(|(path, _, _)| path).collect(),
            store_files,
            passphrase,
            warnings,
        })
    }
}

/// Decrypts a key file with `passphrase`, or returns `None` when the
/// passphrase does not open it.
fn read_key_file(path: &Path, passphrase: &str) -> Result<Option<KeyFile>> {
    let bytes = fs::read(path)?;
    match age::decrypt(passphrase.as_bytes(), &bytes) {
        Ok(plain) => String::from_utf8(plain)
            .ok()
            .and_then(|text| KeyFile::from_text(&text))
            .map(Some)
            .ok_or_else(|| Error::Damaged(file_name(path))),
        Err(age::Error::WrongPassphrase) => Ok(None),
        Err(_) => Err(Error::Damaged(file_name(path))),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// What a store opened or written at `now_ms` leaves out: tombstones go
/// after 120 days, but never while one of the `known` keys, older than the
/// removal, can still open a store file that predates it.
fn cutoffs(known: &BTreeMap<String, (Key, Option<u64>)>, now_ms: u64) -> Cutoffs {
    let mut cutoffs = Cutoffs::at(now_ms);
    let oldest = known.values().map(|(key, _)| key.created).min();
    if let Some(oldest) = oldest {
        cutoffs.tombstones = cutoffs.tombstones.min(oldest.saturating_mul(1000));
    }
    cutoffs
}

fn new_key(created: u64) -> Result<Key> {
    Ok(Key {
        generation: random::id()?,
        created,
        text: random::key_text()?,
    })
}

impl Session {
    /// Fails when another passphrase's key files stayed closed, so nothing
    /// may be written. Saving commands call it before they ask for anything.
    pub fn writable(&self) -> Result<()> {
        match self.passphrase {
            Some(_) => Ok(()),
            None => Err(Error::ReadOnly),
        }
    }

    fn cutoffs(&self, now_ms: u64) -> Cutoffs {
        cutoffs(&self.known, now_ms)
    }

    /// Rotates when the current key is 14 or more days old or more than one
    /// key file opened, and otherwise compacts when more than one store
    /// file was merged. A read-only session does neither.
    pub fn settle(&mut self, vault: &Vault, now_ms: u64) -> Result<Settled> {
        if self.passphrase.is_none() {
            return Ok(Settled::Nothing);
        }
        let age = seconds(now_ms).saturating_sub(self.current.created);
        if age >= ROTATE_AFTER_DAYS * DAY || self.key_files.len() > 1 {
            self.rotate(vault, now_ms, None)?;
            Ok(Settled::Rotated)
        } else if self.store_files.len() > 1 {
            self.save(vault, now_ms)?;
            Ok(Settled::Compacted)
        } else {
            Ok(Settled::Nothing)
        }
    }

    /// Writes the store as a new file under the current key, then deletes
    /// the store files it was merged from.
    pub fn save(&mut self, vault: &Vault, now_ms: u64) -> Result<()> {
        self.writable()?;
        let written =
            vault.write_store_file(&vault.dir, &self.current, &self.store, self.cutoffs(now_ms))?;
        for path in std::mem::take(&mut self.store_files) {
            vault.remove(&path)?;
        }
        self.store_files = vec![written];
        Ok(())
    }

    /// Replaces the vault key: writes a new key file that carries every
    /// known key retired in the last 90 days, writes the store under the new
    /// key, then deletes the store files and key files it read. With
    /// `new_passphrase`, as for `passwd`, the new key file is under it.
    pub fn rotate(
        &mut self,
        vault: &Vault,
        now_ms: u64,
        new_passphrase: Option<String>,
    ) -> Result<()> {
        let (passphrase, passphrase_set) = match (new_passphrase, &self.passphrase) {
            (_, None) => return Err(Error::ReadOnly),
            (Some(new), Some(_)) => (new, seconds(now_ms)),
            (None, Some((old, set))) => (old.clone(), *set),
        };
        let now = seconds(now_ms);
        let key = new_key(now)?;
        let retired: Vec<Retired> = self
            .known
            .values()
            .map(|(key, at)| Retired {
                key: key.clone(),
                retired: at.unwrap_or(now),
            })
            .filter(|r| r.retired + RETIRED_DAYS * DAY >= now)
            .collect();
        let file = KeyFile {
            key: key.clone(),
            passphrase_set,
            retired: retired.clone(),
        };
        vault.write_key_file(&vault.dir, &file, &passphrase)?;
        let cutoffs = self.cutoffs(now_ms);
        let written = vault.write_store_file(&vault.dir, &key, &self.store, cutoffs)?;
        for path in std::mem::take(&mut self.store_files) {
            vault.remove(&path)?;
        }
        for path in std::mem::take(&mut self.key_files) {
            vault.remove(&path)?;
        }

        self.known = retired
            .into_iter()
            .map(|r| (r.key.generation.clone(), (r.key, Some(r.retired))))
            .collect();
        self.known
            .insert(key.generation.clone(), (key.clone(), None));
        self.key_files = vec![vault.dir.join(format!("key.{}.age", key.generation))];
        self.store_files = vec![written];
        self.current = key;
        self.passphrase = Some((passphrase, passphrase_set));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Entry;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FAST: u8 = 10;
    /// A second in milliseconds. Key files keep whole seconds, so changes
    /// that must be ordered by `passphrase-set` are seconds apart.
    const S: u64 = 1000;
    const DAY_MS: u64 = DAY * 1000;
    /// A time in 2026, in milliseconds.
    const T0: u64 = 1_764_000_000_000;

    fn temp_dir() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "multipass-vault-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn secret(s: &str) -> Entry {
        Entry {
            secret: Some(s.into()),
            username: None,
            notes: None,
            otp: None,
        }
    }

    /// Answers the passphrase prompt with `first`, and the prompt for
    /// another passphrase with `second`.
    fn answers(first: &str, second: Option<&str>) -> impl FnMut(Ask) -> io::Result<Option<String>> {
        let first = first.to_string();
        let second = second.map(str::to_string);
        move |ask| {
            Ok(match ask {
                Ask::Passphrase => Some(first.clone()),
                Ask::Other(_) => second.clone(),
            })
        }
    }

    fn open(vault: &Vault, pass: &str, now: u64) -> Session {
        let mut session = vault.open(&mut answers(pass, None), now).unwrap();
        session.settle(vault, now).unwrap();
        session
    }

    fn add(vault: &Vault, pass: &str, name: &str, value: &str, now: u64) {
        let mut session = open(vault, pass, now);
        let stamp = session.store.stamp(now);
        session.store.insert(name, secret(value), stamp);
        session.save(vault, now).unwrap();
    }

    fn remove(vault: &Vault, pass: &str, name: &str, now: u64) {
        let mut session = open(vault, pass, now);
        let stamp = session.store.stamp(now);
        session.store.remove(name, stamp).unwrap();
        session.save(vault, now).unwrap();
    }

    fn names(vault: &Vault, pass: &str, now: u64) -> Vec<String> {
        let session = vault.open(&mut answers(pass, None), now).unwrap();
        session.store.names().map(str::to_string).collect()
    }

    fn files(dir: &Path) -> BTreeSet<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect()
    }

    fn count(dir: &Path, prefix: &str) -> usize {
        files(dir).iter().filter(|n| n.starts_with(prefix)).count()
    }

    fn new_vault(dir: &Path) -> Vault {
        Vault::new(dir.join("store.multipass"), FAST)
    }

    /// Two copies of one package and a copier that plays the part of a sync
    /// service: it brings each side's new files across and applies each
    /// side's deletions, by name, as iCloud Drive or Dropbox would.
    struct Synced {
        a: Vault,
        b: Vault,
        seen_a: BTreeSet<String>,
        seen_b: BTreeSet<String>,
        _root: PathBuf,
    }

    impl Synced {
        fn new(pass: &str, entries: &[(&str, &str)]) -> Synced {
            let root = temp_dir();
            let a = Vault::new(root.join("a.multipass"), FAST);
            a.init(pass, T0).unwrap();
            for (i, (name, value)) in entries.iter().enumerate() {
                add(&a, pass, name, value, T0 + 1 + i as u64);
            }
            let b = Vault::new(root.join("b.multipass"), FAST);
            fs::create_dir(b.dir()).unwrap();
            for name in files(a.dir()) {
                fs::copy(a.dir().join(&name), b.dir().join(&name)).unwrap();
            }
            let seen = files(a.dir());
            Synced {
                a,
                b,
                seen_a: seen.clone(),
                seen_b: seen,
                _root: root,
            }
        }

        /// Applies `from`'s changes since the last sync to `to`. `seen_from`
        /// and `seen_to` are the files the sync service knows each side
        /// holds. A file `to` held and deleted is never brought back, and a
        /// file the service delivers counts as held by `to` from then on, so
        /// its later deletion there travels back.
        fn copy(
            from: &Vault,
            to: &Vault,
            seen_from: &mut BTreeSet<String>,
            seen_to: &mut BTreeSet<String>,
        ) {
            let now = files(from.dir());
            let there = files(to.dir());
            for name in &now {
                if !there.contains(name) && !seen_to.contains(name) {
                    fs::copy(from.dir().join(name), to.dir().join(name)).unwrap();
                    seen_to.insert(name.clone());
                }
            }
            for name in seen_from.difference(&now) {
                let _ = fs::remove_file(to.dir().join(name));
                seen_to.remove(name);
            }
            *seen_from = now;
        }

        fn a_to_b(&mut self) {
            Self::copy(&self.a, &self.b, &mut self.seen_a, &mut self.seen_b);
        }

        fn b_to_a(&mut self) {
            Self::copy(&self.b, &self.a, &mut self.seen_b, &mut self.seen_a);
        }

        /// Syncs until both sides hold the same files, opening each side
        /// between syncs as a prompt would, and returns the names on each.
        fn settle(&mut self, pass: &str, now: u64) -> (Vec<String>, Vec<String>) {
            for _ in 0..4 {
                self.a_to_b();
                self.b_to_a();
                open(&self.a, pass, now);
                self.a_to_b();
                self.b_to_a();
                open(&self.b, pass, now);
            }
            self.a_to_b();
            self.b_to_a();
            assert_eq!(files(self.a.dir()), files(self.b.dir()));
            assert_eq!(count(self.a.dir(), "store."), 1);
            assert_eq!(count(self.a.dir(), "key."), 1);
            (names(&self.a, pass, now), names(&self.b, pass, now))
        }
    }

    /// Every order of the four steps: each side's change and each side's
    /// sync to the other.
    fn interleavings() -> Vec<[usize; 4]> {
        let mut out = Vec::new();
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = [a, b, c, d];
                        if BTreeSet::from(order).len() == 4 {
                            out.push(order);
                        }
                    }
                }
            }
        }
        out
    }

    fn run(synced: &mut Synced, order: [usize; 4], on_a: &dyn Fn(&Vault), on_b: &dyn Fn(&Vault)) {
        for step in order {
            match step {
                0 => on_a(&synced.a),
                1 => on_b(&synced.b),
                2 => synced.a_to_b(),
                _ => synced.b_to_a(),
            }
        }
    }

    #[test]
    fn key_files_round_trip_and_hide_their_keys() {
        let key = |g: char, text: &str| Key {
            generation: g.to_string().repeat(32),
            created: 1_764_000_000,
            text: text.into(),
        };
        let file = KeyFile {
            key: key('a', "mXHnHUSvp+wCWtqvVrFcsN82rLveCB+L/s0F/V5yi9E"),
            passphrase_set: 1_763_000_000,
            retired: vec![Retired {
                key: key('b', "Qm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE"),
                retired: 1_763_500_000,
            }],
        };
        let text = file.to_text();
        assert_eq!(
            text,
            "multipass-key 1\n\
             generation aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
             created 1764000000\n\
             passphrase-set 1763000000\n\
             key mXHnHUSvp+wCWtqvVrFcsN82rLveCB+L/s0F/V5yi9E\n\
             retired bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1764000000 1763500000 \
             Qm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE\n"
        );
        assert_eq!(KeyFile::from_text(&text), Some(file.clone()));
        let debug = format!("{file:?}");
        assert!(
            !debug.contains("mXHn") && !debug.contains("Qm9v"),
            "{debug}"
        );
        for bad in [
            text.replace("multipass-key 1", "multipass-key 2"),
            text.replace("created 1764000000", "created 01764000000"),
            text.replace("generation aaaa", "generation AAAA"),
            text.replace("passphrase-set", "passphrase"),
            text.replace("retired bbbb", "retired-key bbbb"),
        ] {
            assert_eq!(KeyFile::from_text(&bad), None, "{bad}");
        }
    }

    #[test]
    fn init_writes_one_key_file_and_one_store_file_of_its_generation() {
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        let names = files(vault.dir());
        assert_eq!(names.len(), 2, "{names:?}");
        let key = names.iter().find(|n| n.starts_with("key.")).unwrap();
        let store = names.iter().find(|n| n.starts_with("store.")).unwrap();
        let generation = &key["key.".len()..key.len() - ".age".len()];
        assert!(store.starts_with(&format!("store.{generation}.")));
        assert!(!root.join("store.multipass.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(vault.dir()), 0o700);
            for name in &names {
                assert_eq!(mode(&vault.dir().join(name)), 0o600, "{name}");
            }
        }
        assert!(matches!(vault.init("pass", T0), Err(Error::Exists(_))));
    }

    #[test]
    fn opens_with_stock_age_steps() {
        // The recovery steps the README gives: decrypt the key file with
        // the passphrase, then each store file with the key's text.
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        add(&vault, "pass", "github.com", "hunter2", T0 + 1);
        let names = files(vault.dir());
        let key = names.iter().find(|n| n.starts_with("key.")).unwrap();
        let store = names.iter().find(|n| n.starts_with("store.")).unwrap();
        let key_text = String::from_utf8(
            age::decrypt(b"pass", &fs::read(vault.dir().join(key)).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(key_text.starts_with("multipass-key 1\ngeneration "));
        let vault_key = key_text
            .lines()
            .find_map(|l| l.strip_prefix("key "))
            .unwrap();
        let store_text = String::from_utf8(
            age::decrypt(
                vault_key.as_bytes(),
                &fs::read(vault.dir().join(store)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            store_text.starts_with("multipass 3\ngithub.com\n"),
            "{store_text}"
        );
        assert!(store_text.contains("\tsecret hunter2\n"));
    }

    #[test]
    fn a_save_writes_a_new_store_file_and_keeps_the_key_file() {
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        let before = files(vault.dir());
        add(&vault, "pass", "x", "1", T0 + 1);
        let after = files(vault.dir());
        assert_eq!(after.len(), 2);
        let key = |s: &BTreeSet<String>| s.iter().find(|n| n.starts_with("key.")).cloned();
        let store = |s: &BTreeSet<String>| s.iter().find(|n| n.starts_with("store.")).cloned();
        assert_eq!(key(&before), key(&after));
        assert_ne!(store(&before), store(&after));
        assert_eq!(names(&vault, "pass", T0 + 2), ["x"]);
    }

    #[test]
    fn two_saves_at_once_both_survive_in_every_order() {
        for order in interleavings() {
            let mut synced = Synced::new("pass", &[]);
            run(
                &mut synced,
                order,
                &|a| add(a, "pass", "x", "1", T0 + 100 * S),
                &|b| add(b, "pass", "y", "2", T0 + 200 * S),
            );
            let (a, b) = synced.settle("pass", T0 + 300 * S);
            assert_eq!(a, ["x", "y"], "{order:?}");
            assert_eq!(b, ["x", "y"], "{order:?}");
        }
    }

    #[test]
    fn the_later_of_an_edit_and_a_removal_wins_in_every_order() {
        for order in interleavings() {
            let mut synced = Synced::new("pass", &[("x", "1"), ("y", "2")]);
            run(
                &mut synced,
                order,
                &|a| add(a, "pass", "x", "edited", T0 + 100 * S),
                &|b| remove(b, "pass", "x", T0 + 200 * S),
            );
            // B's removal has the later clock, so it wins, unless A's edit
            // came after A saw the removal: then the edit is stamped past
            // it, because a change always wins over one it has seen.
            let at = |step| order.iter().position(|&s| s == step).unwrap();
            let edit_saw_removal = at(1) < at(3) && at(3) < at(0);
            let expected: &[&str] = if edit_saw_removal {
                &["x", "y"]
            } else {
                &["y"]
            };
            let (a, b) = synced.settle("pass", T0 + 300 * S);
            assert_eq!(a, expected, "{order:?}");
            assert_eq!(b, expected, "{order:?}");
        }
    }

    #[test]
    fn a_save_under_the_old_key_survives_a_rotation_in_every_order() {
        for order in interleavings() {
            let mut synced = Synced::new("pass", &[("x", "1")]);
            run(
                &mut synced,
                order,
                &|a| {
                    let mut session = a.open(&mut answers("pass", None), T0 + 100 * S).unwrap();
                    session.rotate(a, T0 + 100 * S, None).unwrap();
                },
                &|b| add(b, "pass", "y", "2", T0 + 200 * S),
            );
            let (a, b) = synced.settle("pass", T0 + 300 * S);
            assert_eq!(a, ["x", "y"], "{order:?}");
            assert_eq!(b, ["x", "y"], "{order:?}");
        }
    }

    #[test]
    fn two_offline_rotations_end_in_one_generation() {
        for order in interleavings() {
            let mut synced = Synced::new("pass", &[("x", "1")]);
            let rotate_adding = |vault: &Vault, name: &str, now: u64| {
                let mut session = vault.open(&mut answers("pass", None), now).unwrap();
                session.rotate(vault, now, None).unwrap();
                let stamp = session.store.stamp(now);
                session.store.insert(name, secret("v"), stamp);
                session.save(vault, now).unwrap();
            };
            run(
                &mut synced,
                order,
                &|a| rotate_adding(a, "a", T0 + 100 * S),
                &|b| rotate_adding(b, "b", T0 + 200 * S),
            );
            let (a, b) = synced.settle("pass", T0 + 300 * S);
            assert_eq!(a, ["a", "b", "x"], "{order:?}");
            assert_eq!(b, ["a", "b", "x"], "{order:?}");
        }
    }

    #[test]
    fn passwd_wins_over_a_rotation_under_the_old_passphrase() {
        for order in interleavings() {
            let mut synced = Synced::new("p1", &[("x", "1")]);
            run(
                &mut synced,
                order,
                &|a| {
                    let mut session = a.open(&mut answers("p1", None), T0 + 100 * S).unwrap();
                    session.rotate(a, T0 + 100 * S, Some("p2".into())).unwrap();
                },
                &|b| {
                    // When A's passwd has already reached B, only the new
                    // passphrase opens B, as it would for you.
                    let mut session = match b.open(&mut answers("p1", None), T0 + 200 * S) {
                        Err(Error::WrongPassphrase) => {
                            b.open(&mut answers("p2", None), T0 + 200 * S).unwrap()
                        }
                        result => result.unwrap(),
                    };
                    session.rotate(b, T0 + 200 * S, None).unwrap();
                    let stamp = session.store.stamp(T0 + 200 * S);
                    session.store.insert("y", secret("2"), stamp);
                    session.save(b, T0 + 200 * S).unwrap();
                },
            );
            synced.a_to_b();
            synced.b_to_a();

            // Wherever both lineages arrived, the old passphrase alone opens
            // a read-only store that saves nothing. When B rotated under
            // the new passphrase because A's passwd reached it first, the
            // old passphrase opens nothing at all.
            let mut old_lineage = false;
            for vault in [&synced.a, &synced.b] {
                let before = files(vault.dir());
                let mut session = match vault.open(&mut answers("p1", None), T0 + 300 * S) {
                    Err(Error::WrongPassphrase) => continue,
                    result => result.unwrap(),
                };
                old_lineage = true;
                if count(vault.dir(), "key.") < 2 {
                    continue;
                }
                assert_eq!(
                    session.settle(vault, T0 + 300 * S).unwrap(),
                    Settled::Nothing
                );
                assert!(matches!(
                    session.save(vault, T0 + 300 * S),
                    Err(Error::ReadOnly)
                ));
                assert_eq!(files(vault.dir()), before, "{order:?}");
            }

            // With both, it rotates under the newer passphrase, whichever
            // you type first, and keeps both changes.
            let (first, second) = if old_lineage {
                ("p1", "p2")
            } else {
                ("p2", "p1")
            };
            let mut asked = 0;
            let mut both = |ask: Ask| {
                Ok(match ask {
                    Ask::Passphrase => Some(first.to_string()),
                    Ask::Other(_) => {
                        asked += 1;
                        Some(second.to_string())
                    }
                })
            };
            let mut session = synced.a.open(&mut both, T0 + 300 * S).unwrap();
            session.settle(&synced.a, T0 + 300 * S).unwrap();
            assert!(asked <= 1);
            synced.a_to_b();
            synced.b_to_a();
            let (a, b) = synced.settle("p2", T0 + 400 * S);
            assert_eq!(a, ["x", "y"], "{order:?}");
            assert_eq!(b, ["x", "y"], "{order:?}");
            assert!(matches!(
                synced.a.open(&mut answers("p1", None), T0 + 500 * S),
                Err(Error::WrongPassphrase)
            ));
        }
    }

    #[test]
    fn a_wrong_passphrase_fails_without_asking_for_another() {
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        let mut asked_other = false;
        let mut ask = |ask: Ask| {
            Ok(match ask {
                Ask::Passphrase => Some("typo".to_string()),
                Ask::Other(_) => {
                    asked_other = true;
                    None
                }
            })
        };
        let err = vault.open(&mut ask, T0).err().unwrap();
        assert!(matches!(err, Error::WrongPassphrase));
        assert_eq!(err.to_string(), "wrong passphrase, or the store is damaged");
        assert!(!asked_other);
    }

    /// Runs `change` against a vault that stops before its `n`th durable
    /// step, for every `n` until the change completes, and checks that the
    /// package then opens with `expected` each time.
    fn at_every_crash_point(
        setup: &dyn Fn(&Vault),
        change: &dyn Fn(&Vault) -> Result<()>,
        check: &dyn Fn(&Vault),
    ) {
        for n in 0.. {
            let root = temp_dir();
            let mut vault = new_vault(&root);
            setup(&vault);
            vault.stop_after = Some(vault.steps.get() + n);
            let result = change(&vault);
            let vault = new_vault(&root);
            check(&vault);
            match result {
                Err(Error::Stopped) => {}
                Ok(()) => break,
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn rotation_compaction_and_init_survive_a_crash_at_every_step() {
        let setup = |vault: &Vault| {
            vault.init("pass", T0).unwrap();
            add(vault, "pass", "x", "1", T0 + 1);
            add(vault, "pass", "y", "2", T0 + 2);
        };
        let check = |vault: &Vault| {
            let mut session = vault.open(&mut answers("pass", None), T0 + 10 * S).unwrap();
            assert_eq!(session.store.names().collect::<Vec<_>>(), ["x", "y"]);
            session.settle(vault, T0 + 10 * S).unwrap();
            assert_eq!(names(vault, "pass", T0 + 11 * S), ["x", "y"]);
        };
        at_every_crash_point(
            &setup,
            &|vault| {
                let mut session = vault.open(&mut answers("pass", None), T0 + 5 * S)?;
                session.rotate(vault, T0 + 5 * S, None)
            },
            &check,
        );
        // A compaction: a second store file, as another Mac's save leaves.
        at_every_crash_point(
            &|vault| {
                setup(vault);
                let session = vault.open(&mut answers("pass", None), T0 + 3).unwrap();
                let mut store = session.store.clone();
                let stamp = store.stamp(T0 + 3);
                store.insert("z", secret("3"), stamp);
                vault
                    .write_store_file(vault.dir(), &session.current, &store, Cutoffs::at(T0))
                    .unwrap();
            },
            &|vault| {
                let mut session = vault.open(&mut answers("pass", None), T0 + 5 * S)?;
                assert_eq!(session.settle(vault, T0 + 5 * S)?, Settled::Compacted);
                Ok(())
            },
            &|vault| {
                assert_eq!(names(vault, "pass", T0 + 10 * S), ["x", "y", "z"]);
            },
        );
        // `init` leaves a whole package or none, and a leftover `.tmp`
        // directory never stops the next attempt.
        for n in 0..3 {
            let root = temp_dir();
            let mut vault = new_vault(&root);
            vault.stop_after = Some(n);
            assert!(matches!(vault.init("pass", T0), Err(Error::Stopped)));
            assert!(!vault.dir().exists());
            vault.stop_after = None;
            vault.init("pass", T0).unwrap();
            assert!(names(&vault, "pass", T0 + 1).is_empty());
        }
    }

    #[test]
    fn a_passwd_cut_short_opens_read_only_with_the_old_passphrase() {
        let root = temp_dir();
        let mut vault = new_vault(&root);
        vault.init("p1", T0).unwrap();
        add(&vault, "p1", "x", "1", T0 + 1);
        vault.stop_after = Some(vault.steps.get() + 1);
        let mut session = vault.open(&mut answers("p1", None), T0 + 5 * S).unwrap();
        assert!(matches!(
            session.rotate(&vault, T0 + 5 * S, Some("p2".into())),
            Err(Error::Stopped)
        ));
        let vault = new_vault(&root);
        assert_eq!(count(vault.dir(), "key."), 2);

        let mut session = vault.open(&mut answers("p1", None), T0 + 6 * S).unwrap();
        assert_eq!(session.store.names().collect::<Vec<_>>(), ["x"]);
        assert_eq!(
            session.settle(&vault, T0 + 6 * S).unwrap(),
            Settled::Nothing
        );
        assert!(matches!(session.writable(), Err(Error::ReadOnly)));

        let mut session = vault
            .open(&mut answers("p1", Some("p2")), T0 + 7 * S)
            .unwrap();
        assert_eq!(
            session.settle(&vault, T0 + 7 * S).unwrap(),
            Settled::Rotated
        );
        assert_eq!(count(vault.dir(), "key."), 1);
        assert!(matches!(
            vault.open(&mut answers("p1", None), T0 + 8 * S),
            Err(Error::WrongPassphrase)
        ));
        assert_eq!(names(&vault, "p2", T0 + 8 * S), ["x"]);
    }

    #[test]
    fn rotates_from_fourteen_days_and_not_again_after() {
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        let mut session = vault.open(&mut answers("pass", None), T0).unwrap();
        let just_before = T0 + 14 * DAY_MS - 60 * 60 * 1000;
        let mut session_before = vault.open(&mut answers("pass", None), just_before).unwrap();
        assert_eq!(
            session_before.settle(&vault, just_before).unwrap(),
            Settled::Nothing
        );
        let at = T0 + 14 * DAY_MS;
        assert_eq!(session.settle(&vault, at).unwrap(), Settled::Rotated);
        let mut next = vault.open(&mut answers("pass", None), at + 1).unwrap();
        assert_eq!(next.settle(&vault, at + 1).unwrap(), Settled::Nothing);
    }

    #[test]
    fn retired_keys_open_old_store_files_for_ninety_days() {
        for (days, merged) in [(89, true), (91, false)] {
            let synced = Synced::new("pass", &[("x", "1")]);
            add(&synced.b, "pass", "y", "2", T0 + 100 * S);
            let mut session = synced
                .a
                .open(&mut answers("pass", None), T0 + 200 * S)
                .unwrap();
            session.rotate(&synced.a, T0 + 200 * S, None).unwrap();
            // B's file under the retired key arrives late.
            let late = files(synced.b.dir())
                .into_iter()
                .find(|n| n.starts_with("store."))
                .unwrap();
            fs::copy(synced.b.dir().join(&late), synced.a.dir().join(&late)).unwrap();

            let now = T0 + 200 * S + days * DAY_MS;
            let session = synced.a.open(&mut answers("pass", None), now).unwrap();
            let names: Vec<_> = session.store.names().collect();
            if merged {
                assert_eq!(names, ["x", "y"], "{days} days");
                assert!(session.warnings.is_empty(), "{:?}", session.warnings);
            } else {
                assert_eq!(names, ["x"], "{days} days");
                assert_eq!(session.warnings.len(), 1);
                assert!(
                    session.warnings[0].contains(&late),
                    "{:?}",
                    session.warnings
                );
            }
        }
    }

    #[test]
    fn tombstones_stay_while_an_older_key_remains() {
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        add(&vault, "pass", "x", "1", T0 + 1);
        remove(&vault, "pass", "x", T0 + 2);
        // Nobody prompts for 200 days, so the key from day 0 is still the
        // current one, and a store file another Mac wrote under it before
        // the removal could still arrive. 120 days alone would drop the
        // tombstone; the day-0 key keeps it through the rotation this
        // prompt runs, and the next open still has it.
        let later = T0 + 200 * DAY_MS;
        assert!(Cutoffs::at(later).tombstones > T0 + 2);
        let mut session = vault.open(&mut answers("pass", None), later).unwrap();
        assert!(session.cutoffs(later).tombstones <= T0);
        assert_eq!(session.settle(&vault, later).unwrap(), Settled::Rotated);
        let session = vault.open(&mut answers("pass", None), later + 1).unwrap();
        assert!(session.store.version("x").is_some());
        assert!(session.store.get("x").is_none());
    }

    #[test]
    fn an_expired_tombstone_in_a_late_file_does_not_bring_its_secret_back() {
        let mut synced = Synced::new("pass", &[("x", "s1")]);
        // A changes x to s2, then removes it; its store file holds the
        // tombstone with s2 and s1 as the removed entry's secrets.
        add(&synced.a, "pass", "x", "s2", T0 + S);
        remove(&synced.a, "pass", "x", T0 + 2 * S);
        // B, which never saw either, edits x 50 days later, past the 30
        // days a removed secret is kept, so B's edit wins.
        let later = T0 + 50 * DAY_MS;
        add(&synced.b, "pass", "x", "s3", later);
        // A's file, written before the 30 days ran out, reaches B late.
        synced.a_to_b();
        let session = synced
            .b
            .open(&mut answers("pass", None), later + S)
            .unwrap();
        let version = session.store.version("x").unwrap();
        assert_eq!(
            session.store.get("x").unwrap().secret.as_deref(),
            Some("s3")
        );
        let earlier: Vec<&str> = version
            .history
            .secrets
            .iter()
            .map(|p| p.value.as_str())
            .collect();
        assert!(!earlier.contains(&"s2"), "{earlier:?}");
        assert_eq!(earlier, ["s1"]);
    }

    #[test]
    fn leaves_foreign_names_alone_and_ignores_temporary_files() {
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        let store = files(vault.dir())
            .into_iter()
            .find(|n| n.starts_with("store."))
            .unwrap();
        let copy = format!("{store} 2");
        fs::copy(vault.dir().join(&store), vault.dir().join(&copy)).unwrap();
        fs::write(vault.dir().join(".half.age.tmp"), b"partial").unwrap();
        fs::write(vault.dir().join(".DS_Store"), b"finder").unwrap();
        let mut session = vault.open(&mut answers("pass", None), T0 + 1).unwrap();
        assert_eq!(session.warnings.len(), 1, "{:?}", session.warnings);
        assert!(session.warnings[0].contains(&copy));
        session.save(&vault, T0 + 1).unwrap();
        assert!(vault.dir().join(&copy).exists());
        assert!(vault.dir().join(".half.age.tmp").exists());
    }

    #[test]
    fn a_package_whose_store_file_has_not_arrived_is_still_syncing() {
        let root = temp_dir();
        let vault = new_vault(&root);
        vault.init("pass", T0).unwrap();
        for name in files(vault.dir()) {
            if name.starts_with("store.") {
                fs::remove_file(vault.dir().join(name)).unwrap();
            }
        }
        let err = vault.open(&mut answers("pass", None), T0).err().unwrap();
        assert_eq!(
            err.to_string(),
            "the store is still syncing; try again shortly"
        );
        let missing = Vault::new(root.join("nowhere.multipass"), FAST);
        assert!(matches!(
            missing.open(&mut answers("pass", None), T0),
            Err(Error::NoStore(_))
        ));
    }
}
