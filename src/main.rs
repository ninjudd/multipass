mod age;
mod clipboard;
mod crypto;
mod otp;
mod store;
mod tty;
mod upgrade;
mod vault;

use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use otp::Otp;
use store::{Entry, Store, Version};
use vault::{Ask, Opened, Session, Vault};

const USAGE: &str = "\
multipass: a small single-user password manager

Usage: multipass [--store <path>] <command>

Commands:
  init                  Create an empty store protected by a new passphrase
  add <name>            Add an entry. The secret is read from stdin when it
                        is piped, and from a hidden prompt otherwise
    --username <value>
    --notes <value>
    --force             Replace the entry's secret, username and notes if it
                        already exists, keeping its one-time password
  get <name>            Print one field of an entry, by default its secret
    --field <field>     secret, username, notes or otp
    --clip              Copy it to the clipboard instead, for 30 seconds
    --previous <n>      An earlier secret, or with --field otp an earlier
                        setup key: 1 is the most recently replaced
  history <name>        List when the entry changed and when each earlier
                        secret and setup key was replaced, without showing
                        them; works for 30 days after rm
  otp <name>            Print the entry's current one-time password code
    --clip              Copy it to the clipboard instead, for 30 seconds
    --set               Store a setup key, an otpauth:// URI or a base32 key,
                        read from stdin when it is piped and from a hidden
                        prompt otherwise. Creates the entry if needed
      --force           Replace the entry's one-time password if it has one
    --clear             Remove the entry's one-time password
  list                  List entry names, one per line
  rm <name>             Remove an entry. restore brings it back for 30 days
  restore <name>        Bring back an entry removed in the past 30 days,
                        with its secret, username, notes and one-time
                        password
  passwd                Change the store's passphrase, and replace its vault key
  rekey                 Replace the vault key now, as for a suspected leak
  upgrade [<version>]   Install the newest release, or the one named, with
                        the installer, checking its attestation when gh is
                        installed. Only this command reaches the network
    --check             Say whether a newer release is out, and change nothing

Options:
  --store <path>        The store package, or $MULTIPASS_STORE
                        [default: ~/.multipass/store.multipass]
  -h, --help            Print this help
  -V, --version         Print the version
";

#[derive(Debug, PartialEq)]
enum Command {
    Init,
    Add {
        name: String,
        username: Option<String>,
        notes: Option<String>,
        force: bool,
    },
    Get {
        name: String,
        field: Field,
        clip: bool,
        previous: Option<usize>,
    },
    History {
        name: String,
    },
    List,
    Rm {
        name: String,
    },
    Restore {
        name: String,
    },
    Otp {
        name: String,
        action: OtpAction,
    },
    Passwd,
    Rekey,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OtpAction {
    Show { clip: bool },
    Set { force: bool },
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Field {
    Secret,
    Username,
    Notes,
    Otp,
}

#[derive(Debug, PartialEq)]
enum Parsed {
    Help,
    Version,
    Run {
        store: Option<PathBuf>,
        command: Command,
    },
    /// Opens no store, so it is not a `Command`.
    Upgrade {
        version: Option<String>,
        check: bool,
    },
}

fn main() -> ExitCode {
    let args: std::result::Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect();
    let result = match args {
        Ok(args) if args.first().is_some_and(|a| a == clipboard::CLEAR_COMMAND) => {
            match &args[1..] {
                [change_count] => clipboard::clear_later(change_count),
                _ => Err("usage: multipass __clear-clipboard <change count>".into()),
            }
        }
        Ok(args) => match parse(args) {
            Err(message) => Err(message),
            Ok(Parsed::Help) => {
                print!("{USAGE}");
                Ok(())
            }
            Ok(Parsed::Version) => {
                println!("multipass {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            Ok(Parsed::Run { store, command }) => run(store, command),
            Ok(Parsed::Upgrade { version, check }) => {
                return run_upgrade(version.as_deref(), check);
            }
        },
        Err(_) => Err("arguments must be valid UTF-8".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("multipass: {message}");
            ExitCode::FAILURE
        }
    }
}

type Result<T> = std::result::Result<T, String>;

fn take_value(
    flag: &str,
    inline: Option<String>,
    args: &mut impl Iterator<Item = String>,
) -> Result<String> {
    match inline {
        Some(value) => Ok(value),
        None => args.next().ok_or_else(|| format!("{flag} needs a value")),
    }
}

fn parse(args: Vec<String>) -> Result<Parsed> {
    let mut store = None;
    let mut username = None;
    let mut notes = None;
    let mut field = None;
    let mut force = false;
    let mut clip = false;
    let mut previous = None;
    let mut otp_action = None;
    let mut check = false;
    let mut positional = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            positional.extend(args.by_ref());
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            positional.push(arg);
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => {
                (flag.to_string(), Some(value.to_string()))
            }
            _ => (arg, None),
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--store" => store = Some(PathBuf::from(take_value(&flag, inline, &mut args)?)),
            "--username" => username = Some(take_value(&flag, inline, &mut args)?),
            "--notes" => notes = Some(take_value(&flag, inline, &mut args)?),
            "--field" => {
                field = Some(match take_value(&flag, inline, &mut args)?.as_str() {
                    "secret" => Field::Secret,
                    "username" => Field::Username,
                    "notes" => Field::Notes,
                    "otp" => Field::Otp,
                    other => {
                        return Err(format!(
                            "unknown field {other}; use secret, username, notes or otp"
                        ));
                    }
                })
            }
            "--previous" => {
                previous = Some(
                    take_value(&flag, inline, &mut args)?
                        .parse::<usize>()
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or("--previous takes a number from 1, the most recently replaced")?,
                )
            }
            "--force" if inline.is_none() => force = true,
            "--clip" if inline.is_none() => clip = true,
            "--clip" => return Err("--clip takes no value".into()),
            "--check" if inline.is_none() => check = true,
            "--check" => return Err("--check takes no value".into()),
            "--set" | "--clear" if inline.is_some() => {
                return Err(format!("{flag} takes no value"));
            }
            "--set" | "--clear" => {
                let action = if flag == "--set" {
                    OtpAction::Set { force: false }
                } else {
                    OtpAction::Clear
                };
                if otp_action
                    .replace(action)
                    .is_some_and(|other| other != action)
                {
                    return Err("--set and --clear cannot be used together".into());
                }
            }
            "--force" => return Err("--force takes no value".into()),
            _ => return Err(format!("unknown option {flag}; see multipass --help")),
        }
    }

    let mut positional = positional.into_iter();
    let Some(command) = positional.next() else {
        return Err("missing command; see multipass --help".into());
    };
    if command == "upgrade" {
        let version = positional
            .next()
            .map(|v| upgrade::release_version(&v))
            .transpose()?;
        if let Some(extra) = positional.next() {
            return Err(format!("unexpected argument {extra}"));
        }
        if check && version.is_some() {
            return Err("upgrade --check takes no version".into());
        }
        let store_flags = store.is_some()
            || username.is_some()
            || notes.is_some()
            || field.is_some()
            || force
            || clip
            || previous.is_some()
            || otp_action.is_some();
        if store_flags {
            return Err("upgrade takes only a version or --check".into());
        }
        return Ok(Parsed::Upgrade { version, check });
    }
    // The store text marks each entry with its name on a line of its own,
    // so an empty name could be saved but never read back.
    let mut name = || {
        positional
            .next()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("{command} needs an entry name"))
    };
    let command = match command.as_str() {
        "help" => return Ok(Parsed::Help),
        "init" => Command::Init,
        "list" => Command::List,
        "passwd" => Command::Passwd,
        "rekey" => Command::Rekey,
        "add" => Command::Add {
            name: name()?,
            username: username.take(),
            notes: notes.take(),
            force: std::mem::take(&mut force),
        },
        "get" => {
            let field = field.take().unwrap_or(Field::Secret);
            if previous.is_some() && !matches!(field, Field::Secret | Field::Otp) {
                return Err("--previous applies only to the secret and otp fields".into());
            }
            Command::Get {
                name: name()?,
                field,
                clip: std::mem::take(&mut clip),
                previous: previous.take(),
            }
        }
        "history" => Command::History { name: name()? },
        "rm" => Command::Rm { name: name()? },
        "restore" => Command::Restore { name: name()? },
        "otp" => Command::Otp {
            name: name()?,
            action: match otp_action.take() {
                None => OtpAction::Show {
                    clip: std::mem::take(&mut clip),
                },
                Some(OtpAction::Set { .. }) => OtpAction::Set {
                    force: std::mem::take(&mut force),
                },
                Some(other) => other,
            },
        },
        other => return Err(format!("unknown command {other}; see multipass --help")),
    };
    if let Some(extra) = positional.next() {
        return Err(format!("unexpected argument {extra}"));
    }
    if username.is_some() || notes.is_some() {
        return Err("--username and --notes only apply to add".into());
    }
    if force {
        return Err("--force only applies to add and otp --set".into());
    }
    if field.is_some() {
        return Err("--field only applies to get".into());
    }
    if clip {
        return Err("--clip only applies to get, and to otp without --set or --clear".into());
    }
    if otp_action.is_some() {
        return Err("--set and --clear only apply to otp".into());
    }
    if previous.is_some() {
        return Err("--previous only applies to get".into());
    }
    if check {
        return Err("--check only applies to upgrade".into());
    }
    Ok(Parsed::Run { store, command })
}

fn run(store: Option<PathBuf>, command: Command) -> Result<()> {
    let place =
        package_path(store.or_else(|| std::env::var_os("MULTIPASS_STORE").map(PathBuf::from)))?;
    let path = place.package;
    if place.named_old && path.exists() {
        if let Some(old) = &place.old {
            eprintln!(
                "note: {} moved to {}; update MULTIPASS_STORE or --store",
                old.display(),
                path.display()
            );
        }
    }
    let vault = Vault::new(&path, age::DEFAULT_WORK_FACTOR).with_old(place.old.clone());
    let now = now_ms()?;
    let save = |session: &mut Session| {
        session
            .save(&vault, now)
            .map_err(|e| write_error(&vault, e))
    };

    match command {
        Command::Init => {
            if path.exists() {
                return Err(format!("a store already exists at {}", path.display()));
            }
            if let Some(old) = place.old.as_ref().filter(|old| old.is_file()) {
                return Err(format!(
                    "a store already exists at {}; any other command moves it into {}",
                    old.display(),
                    path.display()
                ));
            }
            vault
                .init(&new_passphrase()?, now)
                .map_err(|e| e.to_string())?;
            eprintln!("Created {}", path.display());
        }
        Command::Add {
            name,
            username,
            notes,
            force,
        } => {
            let mut session = open_writable(&vault, now)?;
            let store = &mut session.store;
            let existing = store.get(&name);
            if existing.is_some() && !force {
                return Err(format!("{name} already exists; pass --force to replace it"));
            }
            let otp = existing.and_then(|entry| entry.otp.clone());
            let secret = read_hidden(&format!("Secret for {name}: "), "secret")?;
            let stamp = stamp(store, now);
            store.insert(
                name,
                Entry {
                    secret: Some(secret),
                    username,
                    notes,
                    otp,
                },
                stamp,
            );
            save(&mut session)?;
        }
        Command::Get {
            name,
            field,
            clip,
            previous,
        } => {
            let session = open(&vault, now, Settle::Try)?;
            let store = &session.store;
            let value = match previous {
                Some(n) => previous_value(store, &name, field, n)?,
                None => {
                    let entry = store
                        .get(&name)
                        .ok_or_else(|| format!("no entry named {name}"))?;
                    match field {
                        Field::Secret => entry.secret.as_ref(),
                        Field::Username => entry.username.as_ref(),
                        Field::Notes => entry.notes.as_ref(),
                        Field::Otp => entry.otp.as_ref(),
                    }
                    .ok_or_else(|| format!("{name} has no value for that field"))?
                }
            };
            deliver(value, clip)?;
        }
        Command::History { name } => {
            let session = open(&vault, now, Settle::Try)?;
            let version = session
                .store
                .version(&name)
                .ok_or_else(|| format!("no entry named {name}"))?;
            print!("{}", history_text(version));
        }
        Command::List => {
            let session = open(&vault, now, Settle::Try)?;
            for name in session.store.names() {
                println!("{name}");
            }
        }
        Command::Rm { name } => {
            let mut session = open_writable(&vault, now)?;
            let stamp = stamp(&session.store, now);
            session
                .store
                .remove(&name, stamp)
                .ok_or_else(|| format!("no entry named {name}"))?;
            save(&mut session)?;
        }
        Command::Restore { name } => {
            let mut session = open_writable(&vault, now)?;
            let store = &mut session.store;
            let version = store
                .version(&name)
                .ok_or_else(|| format!("no removed entry named {name}"))?;
            if version.entry.is_some() {
                return Err(format!("{name} is not removed"));
            }
            let stamp = stamp(store, now);
            store.restore(&name, stamp).ok_or_else(|| {
                format!("{name} was removed more than 30 days ago and cannot be restored")
            })?;
            save(&mut session)?;
        }
        Command::Otp { name, action } => {
            let mut session = match action {
                OtpAction::Show { .. } => open(&vault, now, Settle::Try)?,
                _ => open_writable(&vault, now)?,
            };
            let store = &mut session.store;
            match action {
                OtpAction::Show { clip } => {
                    let uri = store
                        .get(&name)
                        .ok_or_else(|| format!("no entry named {name}"))?
                        .otp
                        .as_ref()
                        .ok_or_else(|| format!("{name} has no one-time password"))?;
                    let otp = Otp::parse(uri).map_err(|e| e.to_string())?;
                    let now = now / 1000;
                    deliver(&otp.code(now), clip)?;
                    if io::stderr().is_terminal() {
                        eprintln!("expires in {}s", otp.seconds_left(now));
                    }
                }
                OtpAction::Set { force } => {
                    refuse_otp_replacement(store, &name, force)?;
                    let key = read_hidden(&format!("Setup key for {name}: "), "setup key")?;
                    let uri = otp::setup_uri(&key, &name).map_err(|e| e.to_string())?;
                    let entry = match store.get(&name) {
                        Some(entry) => Entry {
                            otp: Some(uri),
                            ..entry.clone()
                        },
                        None => Entry {
                            secret: None,
                            username: None,
                            notes: None,
                            otp: Some(uri),
                        },
                    };
                    let stamp = stamp(store, now);
                    store.insert(name, entry, stamp);
                    save(&mut session)?;
                }
                OtpAction::Clear => {
                    let entry = store
                        .get(&name)
                        .ok_or_else(|| format!("no entry named {name}"))?;
                    if entry.otp.is_none() {
                        return Err(format!("{name} has no one-time password"));
                    }
                    if entry.secret.is_none() {
                        return Err(format!(
                            "{name} holds only a one-time password; use rm to remove the entry"
                        ));
                    }
                    let entry = Entry {
                        otp: None,
                        ..entry.clone()
                    };
                    let stamp = stamp(store, now);
                    store.insert(name, entry, stamp);
                    save(&mut session)?;
                }
            }
        }
        Command::Passwd => {
            let mut session = open_writable_unsettled(&vault, now)?;
            let new = new_passphrase()?;
            session
                .rotate(&vault, now, Some(new))
                .map_err(|e| write_error(&vault, e))?;
            eprintln!("Passphrase changed, and the vault key replaced");
        }
        Command::Rekey => {
            let mut session = open_writable_unsettled(&vault, now)?;
            session
                .rotate(&vault, now, None)
                .map_err(|e| write_error(&vault, e))?;
            eprintln!("Replaced the vault key");
        }
    }
    Ok(())
}

/// Whether `open` rotates or compacts the package when `Session::settle`
/// finds either due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settle {
    /// Settle, but only warn when the package cannot be written, as on a
    /// read-only backup, so a command that only reads still runs.
    Try,
    /// Settle, and fail when that fails, before a command that saves asks
    /// for anything more.
    Must,
    /// Neither rotate nor compact, for `passwd` and `rekey`, which rotate
    /// anyway.
    Skip,
}

/// Opens the store package, asking for the passphrase on the terminal, and
/// settles it as `settle` says. Prints what the open left alone.
fn open(vault: &Vault, now: u64, settle: Settle) -> Result<Session> {
    let mut ask = |ask: Ask| -> io::Result<Option<String>> {
        match ask {
            Ask::Passphrase => terminal_prompt("Passphrase: ").map(Some),
            Ask::Other(files) => {
                eprintln!(
                    "multipass: that passphrase does not open {}, which another Mac's \
                     passwd may have written; type its passphrase, or press return to \
                     open the store read-only",
                    files.join(", ")
                );
                let other = terminal_prompt("Other passphrase: ")?;
                Ok((!other.is_empty()).then_some(other))
            }
            Ask::OldFile(path) => {
                eprintln!(
                    "multipass: {} changed after the move, under a passphrase you have not \
                     typed, such as the one before a passwd; type it to merge the change, or \
                     press return to leave it for now",
                    path.display()
                );
                let old = terminal_prompt("Old file's passphrase: ")?;
                Ok((!old.is_empty()).then_some(old))
            }
        }
    };
    open_with(vault, now, settle, &mut ask)
}

/// Reads a passphrase from the terminal for `Vault::open`, saying, as
/// `prompt` does, that the terminal is what could not be read.
fn terminal_prompt(text: &str) -> io::Result<String> {
    tty::read_hidden(text)
        .map_err(|e| io::Error::new(e.kind(), format!("could not read from the terminal: {e}")))
}

/// `open`, with `ask` answering the passphrase prompts.
fn open_with(
    vault: &Vault,
    now: u64,
    settle: Settle,
    ask: &mut dyn FnMut(Ask) -> io::Result<Option<String>>,
) -> Result<Session> {
    // Only a settle merges the old file, so an open that skips it leaves
    // the old file's passphrase unasked rather than ask for nothing.
    let mut ask = |question: Ask| match question {
        Ask::OldFile(_) if settle == Settle::Skip => Ok(None),
        question => ask(question),
    };
    let (mut session, opened) = vault
        .open_or_move(&mut ask, now)
        .map_err(|e| e.to_string())?;
    let old = vault.old().unwrap_or(vault.path()).display();
    match opened {
        Opened::Package => {}
        Opened::Moved => eprintln!("Moved {old} into {}", vault.path().display()),
        // The old file holds the whole store, so a command that only reads
        // can use it where the package cannot be built.
        Opened::Unmoved(e) => {
            let message = format!("could not move {old}: {}", write_error(vault, e));
            if settle != Settle::Try {
                return Err(message);
            }
            eprintln!("multipass: {message}; reading {old} as it is");
            return Ok(session);
        }
    }
    if session.writable().is_err() {
        eprintln!("multipass: opened read-only; another passphrase was set on another Mac");
    } else if settle != Settle::Skip {
        if let Err(e) = session.settle(vault, now) {
            let message = write_error(vault, e);
            if settle == Settle::Must {
                return Err(message);
            }
            eprintln!("multipass: {message}; the store is read as it is");
        }
    }
    for warning in &session.warnings {
        eprintln!("multipass: {warning}");
    }
    Ok(session)
}

/// Opens the store for a command that saves, failing before it asks for
/// anything more when the store opened read-only or cannot be written.
fn open_writable(vault: &Vault, now: u64) -> Result<Session> {
    let session = open(vault, now, Settle::Must)?;
    session.writable().map_err(|e| e.to_string())?;
    Ok(session)
}

/// Opens the store for `passwd` and `rekey`, which rotate anyway, so it
/// neither rotates nor compacts first.
fn open_writable_unsettled(vault: &Vault, now: u64) -> Result<Session> {
    let session = open(vault, now, Settle::Skip)?;
    session.writable().map_err(|e| e.to_string())?;
    Ok(session)
}

/// The message for a failed write to the package. It names the package
/// when the file system refused, because the OS error alone does not.
fn write_error(vault: &Vault, e: vault::Error) -> String {
    match e {
        vault::Error::Io(e) => format!("could not write to {}: {e}", vault.path().display()),
        e => e.to_string(),
    }
}

/// Milliseconds since the Unix epoch, the unit of the store's stamps.
fn now_ms() -> Result<u64> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock is set before 1970")?;
    Ok(since_epoch.as_millis() as u64)
}

/// The stamp for a change to `store` made at `now`, with a warning when it
/// is dated more than a day ahead because a clock somewhere ran fast.
fn stamp(store: &Store, now: u64) -> u64 {
    let stamp = store.stamp(now);
    if store::dated_in_future(stamp, now) {
        eprintln!(
            "multipass: a change in the store is dated in the future; \
             check the clocks of the machines that sync it"
        );
    }
    stamp
}

/// The `n`th most recently replaced secret, or setup key for `Field::Otp`,
/// of the entry named `name`, live or removed.
fn previous_value<'a>(store: &'a Store, name: &str, field: Field, n: usize) -> Result<&'a str> {
    let history = &store
        .version(name)
        .ok_or_else(|| format!("no entry named {name}"))?
        .history;
    let (list, what) = match field {
        Field::Otp => (&history.otps, "setup key"),
        _ => (&history.secrets, "secret"),
    };
    match list.get(n - 1) {
        Some(previous) => Ok(&previous.value),
        None if list.is_empty() => Err(format!("{name} has no earlier {what}")),
        None => Err(format!(
            "{name} has only {} earlier {what}{}",
            list.len(),
            if list.len() == 1 { "" } else { "s" }
        )),
    }
}

/// Lists when the version changed and when each earlier value was replaced,
/// numbered as `get --previous` counts them. It shows no value.
fn history_text(version: &Version) -> String {
    let what = if version.entry.is_some() {
        "changed"
    } else {
        "removed"
    };
    let mut out = format!("{what:<10} {}\n", utc(version.modified));
    for (field, list) in [
        ("secret", &version.history.secrets),
        ("otp", &version.history.otps),
    ] {
        for (i, previous) in list.iter().enumerate() {
            let label = format!("{field} {}", i + 1);
            out.push_str(&format!("{label:<10} {}\n", utc(previous.replaced)));
        }
    }
    out
}

/// Formats a stamp as a UTC date and time. A stamp of 0 comes from a store
/// written before format 3 recorded when entries changed.
fn utc(ms: u64) -> String {
    if ms == 0 {
        return "unknown".into();
    }
    let seconds = ms / 1000;
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let time = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}

/// Converts days since 1970-01-01 to a Gregorian date with Howard Hinnant's
/// `civil_from_days`, which counts in 400-year eras of years that start on
/// 1 March, so each leap day falls at the end of its year.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    (era * 400 + year_of_era + u64::from(month <= 2), month, day)
}

/// Runs `upgrade` or `upgrade --check`, which end with their own exit
/// statuses: the installer's, or 1 from `--check` when a release is newer.
fn run_upgrade(version: Option<&str>, check: bool) -> ExitCode {
    let result = upgrade::Tools::system().and_then(|tools| {
        if check {
            upgrade::check(&tools, env!("CARGO_PKG_VERSION")).map(|(status, message)| {
                println!("{message}");
                status
            })
        } else {
            upgrade::upgrade(&tools, version)
        }
    });
    match result {
        Ok(status) => ExitCode::from(status),
        Err(failure) => {
            eprintln!("multipass: {}", failure.message);
            ExitCode::from(failure.status)
        }
    }
}

/// Where the store lives. `--store` or `MULTIPASS_STORE` names a package,
/// or a single-file store from an earlier multipass, whose package is the
/// same path ending in `.multipass`. Without either, the package is
/// `~/.multipass/store.multipass`, moved from `~/.multipass/store.age`.
fn package_path(named: Option<PathBuf>) -> Result<Place> {
    if let Some(path) = named {
        // A file is a single-file store from before the package: its
        // package sits beside it, named for it. Once a prompt retires the
        // file, the package beside the name is still the one it means.
        let beside = path.with_extension("multipass");
        let retired = !path.exists() && path != beside && beside.is_dir();
        return Ok(if path.is_file() || retired {
            Place {
                package: beside,
                old: Some(path),
                named_old: true,
            }
        } else {
            Place {
                package: path,
                old: None,
                named_old: false,
            }
        });
    }
    let home =
        std::env::var_os("HOME").ok_or("HOME is not set; pass --store or set MULTIPASS_STORE")?;
    let dir = PathBuf::from(home).join(".multipass");
    Ok(Place {
        package: dir.join("store.multipass"),
        old: Some(dir.join("store.age")),
        named_old: false,
    })
}

/// Where the store lives: its package, the single-file store from before
/// the package that it was or will be moved from, and whether `--store` or
/// `MULTIPASS_STORE` named that old file rather than the package.
struct Place {
    package: PathBuf,
    old: Option<PathBuf>,
    named_old: bool,
}

/// Returns an error naming the entry when it already has a one-time password
/// and `force` is false. A replaced setup key cannot be recovered, and losing
/// it can lock you out of the account, so call this before reading the key,
/// and a refusal then asks for nothing.
fn refuse_otp_replacement(store: &Store, name: &str, force: bool) -> Result<()> {
    if !force && store.get(name).is_some_and(|entry| entry.otp.is_some()) {
        return Err(format!(
            "{name} already has a one-time password; pass --force to replace it"
        ));
    }
    Ok(())
}

fn prompt(text: &str) -> Result<String> {
    tty::read_hidden(text).map_err(|e| format!("could not read from the terminal: {e}"))
}

fn new_passphrase() -> Result<String> {
    let first = prompt("New passphrase: ")?;
    if first.is_empty() {
        return Err("the passphrase cannot be empty".into());
    }
    if prompt("Repeat it: ")? != first {
        return Err("the passphrases did not match".into());
    }
    Ok(first)
}

/// Reads a value that must never reach argv: from stdin when it is piped, and
/// otherwise from a hidden prompt typed twice. `what` names it in errors.
fn read_hidden(prompt_text: &str, what: &str) -> Result<String> {
    let value = if io::stdin().is_terminal() {
        let first = prompt(prompt_text)?;
        if prompt("Repeat it: ")? != first {
            return Err(format!("the {what}s did not match"));
        }
        first
    } else {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| format!("could not read the {what} from stdin: {e}"))?;
        strip_newline(input)
    };
    if value.is_empty() {
        return Err(format!("the {what} cannot be empty"));
    }
    Ok(value)
}

/// Drops the one trailing newline that `echo` or `op read` adds.
fn strip_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Prints `value`, or with `clip` copies it to the clipboard for
/// `clipboard::CLEAR_AFTER` and says so on stderr without showing it.
fn deliver(value: &str, clip: bool) -> Result<()> {
    if !clip {
        return print_value(value);
    }
    clipboard::copy(value)?;
    eprintln!(
        "Copied to the clipboard; it clears in {}s",
        clipboard::CLEAR_AFTER.as_secs()
    );
    Ok(())
}

/// Prints a value with a trailing newline only on a terminal, so
/// `multipass get x | pbcopy` copies exactly the secret.
fn print_value(value: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    let result = if stdout.is_terminal() {
        writeln!(stdout, "{value}")
    } else {
        write!(stdout, "{value}")
    };
    result
        .and_then(|()| stdout.flush())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    fn run_of(s: &str) -> Command {
        match parse(args(s)).unwrap() {
            Parsed::Run { command, .. } => command,
            other => panic!("{s:?} parsed as {other:?}"),
        }
    }

    #[test]
    fn parses_commands_and_flags() {
        assert_eq!(run_of("init"), Command::Init);
        assert_eq!(run_of("list"), Command::List);
        assert_eq!(run_of("rekey"), Command::Rekey);
        assert_eq!(
            run_of("restore github.com"),
            Command::Restore {
                name: "github.com".into()
            }
        );
        assert_eq!(
            run_of("add github.com --username octocat --force"),
            Command::Add {
                name: "github.com".into(),
                username: Some("octocat".into()),
                notes: None,
                force: true,
            }
        );
        assert_eq!(
            run_of("--notes=hi add x"),
            Command::Add {
                name: "x".into(),
                username: None,
                notes: Some("hi".into()),
                force: false,
            }
        );
        assert_eq!(
            run_of("get x --field username"),
            Command::Get {
                name: "x".into(),
                field: Field::Username,
                clip: false,
                previous: None,
            }
        );
        assert_eq!(
            run_of("rm -- --odd-name"),
            Command::Rm {
                name: "--odd-name".into()
            }
        );
        assert_eq!(
            parse(args("--store /tmp/s.age list")).unwrap(),
            Parsed::Run {
                store: Some("/tmp/s.age".into()),
                command: Command::List,
            }
        );
        assert_eq!(parse(args("--help")).unwrap(), Parsed::Help);
        assert_eq!(parse(args("help")).unwrap(), Parsed::Help);
        assert_eq!(parse(args("-V")).unwrap(), Parsed::Version);
    }

    #[test]
    fn parses_the_otp_command() {
        for (argv, action) in [
            ("otp github.com", OtpAction::Show { clip: false }),
            ("otp github.com --clip", OtpAction::Show { clip: true }),
            ("otp github.com --set", OtpAction::Set { force: false }),
            ("otp --clear github.com", OtpAction::Clear),
            (
                "otp github.com --set --set",
                OtpAction::Set { force: false },
            ),
            (
                "otp github.com --set --force",
                OtpAction::Set { force: true },
            ),
            (
                "otp --force github.com --set",
                OtpAction::Set { force: true },
            ),
        ] {
            assert_eq!(
                run_of(argv),
                Command::Otp {
                    name: "github.com".into(),
                    action
                },
                "{argv}"
            );
        }
        assert_eq!(
            run_of("get github.com --field otp"),
            Command::Get {
                name: "github.com".into(),
                field: Field::Otp,
                clip: false,
                previous: None,
            }
        );
        assert_eq!(
            run_of("get --clip github.com --field username"),
            Command::Get {
                name: "github.com".into(),
                field: Field::Username,
                clip: true,
                previous: None,
            }
        );
    }

    #[test]
    fn parses_the_upgrade_command() {
        let upgrade = |s: &str| parse(args(s)).unwrap();
        assert_eq!(
            upgrade("upgrade"),
            Parsed::Upgrade {
                version: None,
                check: false
            }
        );
        assert_eq!(
            upgrade("upgrade 0.2.0"),
            Parsed::Upgrade {
                version: Some("0.2.0".into()),
                check: false
            }
        );
        assert_eq!(
            upgrade("upgrade v0.2.0"),
            Parsed::Upgrade {
                version: Some("0.2.0".into()),
                check: false
            }
        );
        assert_eq!(
            upgrade("upgrade --check"),
            Parsed::Upgrade {
                version: None,
                check: true
            }
        );
        for bad in [
            "upgrade --check 0.2.0",
            "upgrade 0.2.0 0.3.0",
            "upgrade 0.2",
            "upgrade ../0.2.0",
            "upgrade --check=yes",
            "--store /tmp/s.age upgrade",
            "upgrade --force",
            "upgrade --clip",
            "upgrade --previous 1",
            "list --check",
            "get x --check",
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn rejects_bad_arguments() {
        for bad in [
            "",
            "frobnicate",
            "add",
            "get x y",
            "list --force",
            "get x --username u",
            "add x --field secret",
            "get x --field password",
            "add x --clip",
            "list --clip",
            "otp x --set --clip",
            "otp x --clear --clip",
            "get x --clip=yes",
            "add x --force=yes",
            "list --verbose",
            "list --store",
            "otp",
            "otp x --set --clear",
            "otp x --clear --set",
            "otp x --set=yes",
            "add x --set",
            "get x --clear",
            "otp x --field otp",
            "get x --field code",
            "otp x --force",
            "otp x --clear --force",
            "otp x --set --force=yes",
            "get x --force",
            "rm x --force",
            "get x --previous",
            "get x --previous 0",
            "get x --previous -1",
            "get x --previous two",
            "get x --previous 1 --field username",
            "get x --field notes --previous 1",
            "add x --previous 1",
            "history x --previous 1",
            "otp x --previous 1",
            "history",
            "history x y",
            "history x --clip",
            "restore",
            "restore x y",
            "restore x --force",
            "restore x --previous 1",
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?} parsed");
        }
        // The store text cannot hold an entry with no name.
        for command in ["add", "get", "rm", "restore", "otp", "history"] {
            let argv = vec![command.to_string(), String::new()];
            assert!(parse(argv).is_err(), "{command} with an empty name parsed");
        }
    }

    #[test]
    fn otp_set_replaces_a_one_time_password_only_when_forced() {
        let entry = |otp: Option<&str>| Entry {
            secret: Some("s".into()),
            username: None,
            notes: None,
            otp: otp.map(String::from),
        };
        let mut store = Store::new();
        store.insert(
            "with",
            entry(Some("otpauth://totp/with?secret=JBSWY3DPEHPK3PXP")),
            1,
        );
        store.insert("without", entry(None), 1);

        assert_eq!(
            refuse_otp_replacement(&store, "with", false).unwrap_err(),
            "with already has a one-time password; pass --force to replace it"
        );
        assert!(refuse_otp_replacement(&store, "with", true).is_ok());
        assert!(refuse_otp_replacement(&store, "without", false).is_ok());
        assert!(refuse_otp_replacement(&store, "missing", false).is_ok());
    }

    #[test]
    fn parses_history_and_previous() {
        assert_eq!(
            run_of("history github.com"),
            Command::History {
                name: "github.com".into()
            }
        );
        for (argv, field, clip) in [
            ("get x --previous 2", Field::Secret, false),
            ("get x --previous=2 --clip", Field::Secret, true),
            ("get --field otp x --previous 2", Field::Otp, false),
        ] {
            assert_eq!(
                run_of(argv),
                Command::Get {
                    name: "x".into(),
                    field,
                    clip,
                    previous: Some(2),
                },
                "{argv}"
            );
        }
    }

    fn store_with_history() -> Store {
        let entry = |secret: &str, otp: Option<&str>| Entry {
            secret: Some(secret.into()),
            username: None,
            notes: None,
            otp: otp.map(String::from),
        };
        let otp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
        let mut store = Store::new();
        store.insert("x", entry("first", Some(otp)), 1_764_160_000_123);
        store.insert("x", entry("second", None), 1_764_160_060_000);
        store.insert("x", entry("third", None), 1_764_246_400_000);
        store.insert("gone", entry("kept", None), 1_000);
        store.remove("gone", 2_000);
        store
    }

    #[test]
    fn previous_counts_from_the_most_recently_replaced() {
        let store = store_with_history();
        let get = |name: &str, field: Field, n: usize| previous_value(&store, name, field, n);
        assert_eq!(get("x", Field::Secret, 1).unwrap(), "second");
        assert_eq!(get("x", Field::Secret, 2).unwrap(), "first");
        assert_eq!(
            get("x", Field::Otp, 1).unwrap(),
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
        );
        assert_eq!(get("gone", Field::Secret, 1).unwrap(), "kept");
        // The errors count what is kept and never show a value.
        assert_eq!(
            get("x", Field::Secret, 3).unwrap_err(),
            "x has only 2 earlier secrets"
        );
        assert_eq!(
            get("x", Field::Otp, 2).unwrap_err(),
            "x has only 1 earlier setup key"
        );
        assert_eq!(
            get("gone", Field::Otp, 1).unwrap_err(),
            "gone has no earlier setup key"
        );
        assert_eq!(
            get("missing", Field::Secret, 1).unwrap_err(),
            "no entry named missing"
        );
    }

    #[test]
    fn history_lists_dates_and_no_values() {
        let store = store_with_history();
        let text = history_text(store.version("x").unwrap());
        assert_eq!(
            text,
            "changed    2025-11-27 12:26:40 UTC\n\
             secret 1   2025-11-27 12:26:40 UTC\n\
             secret 2   2025-11-26 12:27:40 UTC\n\
             otp 1      2025-11-26 12:27:40 UTC\n"
        );
        for secret in ["first", "second", "third", "JBSWY3DPEHPK3PXP"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert_eq!(
            history_text(store.version("gone").unwrap()),
            "removed    1970-01-01 00:00:02 UTC\nsecret 1   1970-01-01 00:00:02 UTC\n"
        );
        let old = Store::from_text("multipass 2\nx\n\tsecret s\n").unwrap();
        assert_eq!(
            history_text(old.version("x").unwrap()),
            "changed    unknown\n"
        );
    }

    #[test]
    fn formats_utc_dates() {
        assert_eq!(utc(1_764_160_000_123), "2025-11-26 12:26:40 UTC");
        assert_eq!(utc(1_709_164_800_000), "2024-02-29 00:00:00 UTC");
        assert_eq!(utc(951_782_399_000), "2000-02-28 23:59:59 UTC");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(1), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn strips_exactly_one_newline() {
        assert_eq!(strip_newline("a\n".into()), "a");
        assert_eq!(strip_newline("a\r\n".into()), "a");
        assert_eq!(strip_newline("a\n\n".into()), "a\n");
        assert_eq!(strip_newline("a".into()), "a");
    }

    /// A package due to rotate, or to compact, in a folder this process
    /// cannot write, as on a read-only backup: a command that reads still
    /// gets the store, and one that saves fails, naming the package.
    #[test]
    fn reads_a_package_it_cannot_write_and_refuses_to_save_to_it() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        const DAY_MS: u64 = 24 * 60 * 60 * 1000;
        const T0: u64 = 1_764_000_000_000;
        let mut ask = |_: Ask| -> io::Result<Option<String>> { Ok(Some("pass".into())) };
        let cases = [
            ("a 15-day-old key", T0 + 15 * DAY_MS, false),
            ("two store files", T0 + 1000, true),
        ];
        for (i, (case, later, second_store_file)) in cases.into_iter().enumerate() {
            let root = std::env::temp_dir()
                .join(format!("multipass-main-test-{}-{i}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            let vault = Vault::new(root.join("store.multipass"), 10);
            vault.init("pass", T0).unwrap();
            let mut session = open_with(&vault, T0, Settle::Skip, &mut ask).unwrap();
            let entry = Entry {
                secret: Some("s".into()),
                username: None,
                notes: None,
                otp: None,
            };
            session.store.insert("x", entry, T0);
            session.save(&vault, T0).unwrap();
            if second_store_file {
                let file = fs::read_dir(vault.path())
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| {
                        p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with("store.")
                    })
                    .unwrap();
                // The same store under another random part of the name, as a
                // second Mac's save would be.
                let name = file.file_name().unwrap().to_string_lossy().into_owned();
                let generation = name.split('.').nth(1).unwrap();
                let other = format!("store.{generation}.{}.age", "0".repeat(32));
                fs::copy(&file, vault.path().join(other)).unwrap();
            }
            let mode = |m| fs::set_permissions(vault.path(), fs::Permissions::from_mode(m));
            mode(0o500).unwrap();

            let mut read = open_with(&vault, later, Settle::Try, &mut ask);
            let saving = open_with(&vault, later, Settle::Must, &mut ask).err();
            let save = read
                .as_mut()
                .ok()
                .map(|s| s.save(&vault, later).map_err(|e| write_error(&vault, e)));

            mode(0o700).unwrap();
            fs::remove_dir_all(&root).unwrap();

            let read = read.unwrap_or_else(|e| panic!("{case}: {e}"));
            assert_eq!(read.store.get("x").unwrap().secret.as_deref(), Some("s"));
            let refused = format!("could not write to {}: ", vault.path().display());
            let saving = saving.unwrap_or_else(|| panic!("{case}: a saving open succeeded"));
            assert!(saving.starts_with(&refused), "{case}: {saving}");
            let save = save.unwrap().unwrap_err();
            assert!(save.starts_with(&refused), "{case}: {save}");
        }
    }

    /// An old single-file store in a folder this process cannot write, as
    /// in a read-only backup: a command that reads gets the old store as it
    /// is, and one that saves, rotates or changes the passphrase fails,
    /// naming the folder, before it asks for anything more.
    #[test]
    fn reads_an_old_store_it_cannot_move_and_refuses_to_save_to_it() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("multipass-main-old-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let old = root.join("store.age");
        let text = "multipass 2\nexample.com\n\tsecret hunter2\n";
        fs::write(&old, age::encrypt(b"pass", text.as_bytes(), 10).unwrap()).unwrap();
        let vault = Vault::new(root.join("store.multipass"), 10).with_old(Some(old.clone()));
        let mut ask = |_: Ask| -> io::Result<Option<String>> { Ok(Some("pass".into())) };
        let mode = |m| fs::set_permissions(&root, fs::Permissions::from_mode(m));
        mode(0o500).unwrap();

        let now = 1_764_000_000_000;
        let read = open_with(&vault, now, Settle::Try, &mut ask);
        let saving = open_with(&vault, now, Settle::Must, &mut ask).err();
        let rekeying = open_with(&vault, now, Settle::Skip, &mut ask).err();
        let package_made = vault.path().exists();

        mode(0o700).unwrap();
        fs::remove_dir_all(&root).unwrap();

        let read = read.unwrap_or_else(|e| panic!("{e}"));
        let secret = read.store.get("example.com").unwrap().secret.as_deref();
        assert_eq!(secret, Some("hunter2"));
        assert!(!package_made);
        let refused = format!(
            "could not move {}: could not write to {}: ",
            old.display(),
            vault.path().display()
        );
        for error in [saving, rekeying] {
            let error = error.expect("an open that writes succeeded");
            assert!(error.starts_with(&refused), "{error}");
        }
    }

    /// `--store` naming the old single-file store keeps opening its package
    /// once a prompt has retired the old file, and a path that names
    /// nothing, with no package beside it, is a new package for `init`.
    #[test]
    fn a_named_old_file_opens_its_package_after_it_is_retired() {
        use std::fs;

        let root =
            std::env::temp_dir().join(format!("multipass-main-named-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("store.multipass")).unwrap();
        let old = root.join("store.age");
        let retired = package_path(Some(old.clone())).unwrap();
        fs::write(&old, b"old").unwrap();
        let present = package_path(Some(old.clone())).unwrap();
        let new = package_path(Some(root.join("other"))).unwrap();
        fs::remove_dir_all(&root).unwrap();

        for place in [&retired, &present] {
            assert_eq!(place.package, root.join("store.multipass"));
            assert_eq!(place.old.as_deref(), Some(old.as_path()));
            assert!(place.named_old);
        }
        assert_eq!(new.package, root.join("other"));
        assert_eq!(new.old, None);
        assert!(!new.named_old);
    }

    /// `passwd` and `rekey` neither rotate first nor merge the old file, so
    /// they never ask for its passphrase; a command that settles does.
    #[test]
    fn asks_for_an_old_files_passphrase_only_when_the_open_settles() {
        use std::cell::Cell;
        use std::fs;

        let root =
            std::env::temp_dir().join(format!("multipass-main-oldask-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let old = root.join("store.age");
        let write_old = |text: &str| {
            fs::write(&old, age::encrypt(b"pass", text.as_bytes(), 10).unwrap()).unwrap();
        };
        write_old("multipass 2\nx\n\tsecret 1\n");
        let vault = Vault::new(root.join("store.multipass"), 10).with_old(Some(old.clone()));
        let now = 1_764_000_000_000;
        let mut first = |_: Ask| -> io::Result<Option<String>> { Ok(Some("pass".into())) };
        let mut session = open_with(&vault, now, Settle::Try, &mut first).unwrap();
        session
            .rotate(&vault, now + 1000, Some("new".into()))
            .unwrap();
        // An older multipass saves to the old file under the earlier passphrase.
        write_old("multipass 2\nx\n\tsecret 1\nz\n\tsecret 3\n");

        let asked = Cell::new(false);
        let mut ask = |question: Ask| -> io::Result<Option<String>> {
            Ok(Some(match question {
                Ask::OldFile(_) => {
                    asked.set(true);
                    "pass".into()
                }
                _ => "new".into(),
            }))
        };
        open_with(&vault, now + 2000, Settle::Skip, &mut ask).unwrap();
        let asked_unsettled = asked.get();
        let settled = open_with(&vault, now + 3000, Settle::Must, &mut ask).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert!(!asked_unsettled, "an open that does not settle asked");
        assert!(asked.get(), "an open that settles did not ask");
        assert!(settled.store.get("z").is_some());
    }
}
