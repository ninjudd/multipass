mod age;
mod clipboard;
mod crypto;
mod otp;
mod store;
mod tty;

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use otp::Otp;
use store::{Cutoffs, Entry, Store, Version};

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
  rm <name>             Remove an entry. Its secrets stay recoverable with
                        get --previous for 30 days
  passwd                Change the store's passphrase

Options:
  --store <path>        The store file, or $MULTIPASS_STORE
                        [default: ~/.multipass/store.age]
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
    Otp {
        name: String,
        action: OtpAction,
    },
    Passwd,
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
        Ok(args) => parse(args).and_then(|parsed| match parsed {
            Parsed::Help => {
                print!("{USAGE}");
                Ok(())
            }
            Parsed::Version => {
                println!("multipass {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            Parsed::Run { store, command } => run(store, command),
        }),
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
    Ok(Parsed::Run { store, command })
}

fn run(store: Option<PathBuf>, command: Command) -> Result<()> {
    let path = match store.or_else(|| std::env::var_os("MULTIPASS_STORE").map(PathBuf::from)) {
        Some(path) => path,
        None => default_store_path()?,
    };
    let now = now_ms()?;
    let save = |store: &Store, passphrase: &str| {
        store
            .save(
                &path,
                passphrase,
                age::DEFAULT_WORK_FACTOR,
                Cutoffs::at(now),
            )
            .map_err(|e| e.to_string())
    };

    match command {
        Command::Init => {
            if path.exists() {
                return Err(format!("a store already exists at {}", path.display()));
            }
            save(&Store::new(), &new_passphrase()?)?;
            eprintln!("Created {}", path.display());
        }
        Command::Add {
            name,
            username,
            notes,
            force,
        } => {
            let (mut store, passphrase) = open(&path, now)?;
            let existing = store.get(&name);
            if existing.is_some() && !force {
                return Err(format!("{name} already exists; pass --force to replace it"));
            }
            let otp = existing.and_then(|entry| entry.otp.clone());
            let secret = read_hidden(&format!("Secret for {name}: "), "secret")?;
            let stamp = stamp(&store, now);
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
            save(&store, &passphrase)?;
        }
        Command::Get {
            name,
            field,
            clip,
            previous,
        } => {
            let (store, _) = open(&path, now)?;
            let value = match previous {
                Some(n) => previous_value(&store, &name, field, n)?,
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
            let (store, _) = open(&path, now)?;
            let version = store
                .version(&name)
                .ok_or_else(|| format!("no entry named {name}"))?;
            print!("{}", history_text(version));
        }
        Command::List => {
            let (store, _) = open(&path, now)?;
            for name in store.names() {
                println!("{name}");
            }
        }
        Command::Rm { name } => {
            let (mut store, passphrase) = open(&path, now)?;
            let stamp = stamp(&store, now);
            store
                .remove(&name, stamp)
                .ok_or_else(|| format!("no entry named {name}"))?;
            save(&store, &passphrase)?;
        }
        Command::Otp { name, action } => {
            let (mut store, passphrase) = open(&path, now)?;
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
                    refuse_otp_replacement(&store, &name, force)?;
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
                    let stamp = stamp(&store, now);
                    store.insert(name, entry, stamp);
                    save(&store, &passphrase)?;
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
                    let stamp = stamp(&store, now);
                    store.insert(name, entry, stamp);
                    save(&store, &passphrase)?;
                }
            }
        }
        Command::Passwd => {
            let (store, _) = open(&path, now)?;
            save(&store, &new_passphrase()?)?;
            eprintln!("Passphrase changed");
        }
    }
    Ok(())
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

fn default_store_path() -> Result<PathBuf> {
    let home =
        std::env::var_os("HOME").ok_or("HOME is not set; pass --store or set MULTIPASS_STORE")?;
    Ok(PathBuf::from(home).join(".multipass").join("store.age"))
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

/// Opens the store as of `now`, without what the next write would drop, so a
/// removed secret past its 30 days is gone even before that write.
fn open(path: &Path, now: u64) -> Result<(Store, String)> {
    let passphrase = prompt("Passphrase: ")?;
    let mut store = Store::load(path, &passphrase).map_err(|e| e.to_string())?;
    store.expire(Cutoffs::at(now));
    Ok((store, passphrase))
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
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?} parsed");
        }
        // The store text cannot hold an entry with no name.
        for command in ["add", "get", "rm", "otp", "history"] {
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
}
