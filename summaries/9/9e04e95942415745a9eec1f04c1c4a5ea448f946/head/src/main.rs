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
use store::{Entry, Store};

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
  otp <name>            Print the entry's current one-time password code
    --clip              Copy it to the clipboard instead, for 30 seconds
    --set               Store a setup key, an otpauth:// URI or a base32 key,
                        read from stdin when it is piped and from a hidden
                        prompt otherwise. Creates the entry if needed
      --force           Replace the entry's one-time password if it has one
    --clear             Remove the entry's one-time password
  list                  List entry names, one per line
  rm <name>             Remove an entry
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
        "get" => Command::Get {
            name: name()?,
            field: field.take().unwrap_or(Field::Secret),
            clip: std::mem::take(&mut clip),
        },
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
        return Err("--clip only applies to get and otp".into());
    }
    if otp_action.is_some() {
        return Err("--set and --clear only apply to otp".into());
    }
    Ok(Parsed::Run { store, command })
}

fn run(store: Option<PathBuf>, command: Command) -> Result<()> {
    let path = match store.or_else(|| std::env::var_os("MULTIPASS_STORE").map(PathBuf::from)) {
        Some(path) => path,
        None => default_store_path()?,
    };
    let save = |store: &Store, passphrase: &str| {
        store
            .save(&path, passphrase, age::DEFAULT_WORK_FACTOR)
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
            let (mut store, passphrase) = open(&path)?;
            let existing = store.get(&name);
            if existing.is_some() && !force {
                return Err(format!("{name} already exists; pass --force to replace it"));
            }
            let otp = existing.and_then(|entry| entry.otp.clone());
            let secret = read_hidden(&format!("Secret for {name}: "), "secret")?;
            store.insert(
                name,
                Entry {
                    secret: Some(secret),
                    username,
                    notes,
                    otp,
                },
            );
            save(&store, &passphrase)?;
        }
        Command::Get { name, field, clip } => {
            let (store, _) = open(&path)?;
            let entry = store
                .get(&name)
                .ok_or_else(|| format!("no entry named {name}"))?;
            let value = match field {
                Field::Secret => entry.secret.as_ref(),
                Field::Username => entry.username.as_ref(),
                Field::Notes => entry.notes.as_ref(),
                Field::Otp => entry.otp.as_ref(),
            }
            .ok_or_else(|| format!("{name} has no value for that field"))?;
            deliver(value, clip)?;
        }
        Command::List => {
            let (store, _) = open(&path)?;
            for name in store.names() {
                println!("{name}");
            }
        }
        Command::Rm { name } => {
            let (mut store, passphrase) = open(&path)?;
            store
                .remove(&name)
                .ok_or_else(|| format!("no entry named {name}"))?;
            save(&store, &passphrase)?;
        }
        Command::Otp { name, action } => {
            let (mut store, passphrase) = open(&path)?;
            match action {
                OtpAction::Show { clip } => {
                    let uri = store
                        .get(&name)
                        .ok_or_else(|| format!("no entry named {name}"))?
                        .otp
                        .as_ref()
                        .ok_or_else(|| format!("{name} has no one-time password"))?;
                    let otp = Otp::parse(uri).map_err(|e| e.to_string())?;
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "the system clock is set before 1970")?
                        .as_secs();
                    deliver(&otp.code(now), clip)?;
                    if io::stderr().is_terminal() {
                        eprintln!("expires in {}s", otp.seconds_left(now));
                    }
                }
                OtpAction::Set { force } => {
                    refuse_otp_replacement(&store, &name, force)?;
                    let key = read_hidden(&format!("Setup key for {name}: "), "setup key")?;
                    let uri = otp::setup_uri(&key, &name).map_err(|e| e.to_string())?;
                    match store.get_mut(&name) {
                        Some(entry) => entry.otp = Some(uri),
                        None => {
                            store.insert(
                                name,
                                Entry {
                                    secret: None,
                                    username: None,
                                    notes: None,
                                    otp: Some(uri),
                                },
                            );
                        }
                    }
                    save(&store, &passphrase)?;
                }
                OtpAction::Clear => {
                    let entry = store
                        .get_mut(&name)
                        .ok_or_else(|| format!("no entry named {name}"))?;
                    if entry.otp.is_none() {
                        return Err(format!("{name} has no one-time password"));
                    }
                    if entry.secret.is_none() {
                        return Err(format!(
                            "{name} holds only a one-time password; use rm to remove the entry"
                        ));
                    }
                    entry.otp = None;
                    save(&store, &passphrase)?;
                }
            }
        }
        Command::Passwd => {
            let (store, _) = open(&path)?;
            save(&store, &new_passphrase()?)?;
            eprintln!("Passphrase changed");
        }
    }
    Ok(())
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

fn open(path: &Path) -> Result<(Store, String)> {
    let passphrase = prompt("Passphrase: ")?;
    let store = Store::load(path, &passphrase).map_err(|e| e.to_string())?;
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
            }
        );
        assert_eq!(
            run_of("get --clip github.com --field username"),
            Command::Get {
                name: "github.com".into(),
                field: Field::Username,
                clip: true,
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
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?} parsed");
        }
        // The store text cannot hold an entry with no name.
        for command in ["add", "get", "rm", "otp"] {
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
        );
        store.insert("without", entry(None));

        assert_eq!(
            refuse_otp_replacement(&store, "with", false).unwrap_err(),
            "with already has a one-time password; pass --force to replace it"
        );
        assert!(refuse_otp_replacement(&store, "with", true).is_ok());
        assert!(refuse_otp_replacement(&store, "without", false).is_ok());
        assert!(refuse_otp_replacement(&store, "missing", false).is_ok());
    }

    #[test]
    fn strips_exactly_one_newline() {
        assert_eq!(strip_newline("a\n".into()), "a");
        assert_eq!(strip_newline("a\r\n".into()), "a");
        assert_eq!(strip_newline("a\n\n".into()), "a\n");
        assert_eq!(strip_newline("a".into()), "a");
    }
}
