mod age;
mod crypto;
mod store;
mod tty;

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    --force             Replace the entry if it already exists
  get <name>            Print one field of an entry, by default its secret
    --field <field>     secret, username or notes
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
    },
    List,
    Rm {
        name: String,
    },
    Passwd,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Field {
    Secret,
    Username,
    Notes,
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
                    other => {
                        return Err(format!(
                            "unknown field {other}; use secret, username or notes"
                        ));
                    }
                })
            }
            "--force" if inline.is_none() => force = true,
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
        },
        "rm" => Command::Rm { name: name()? },
        other => return Err(format!("unknown command {other}; see multipass --help")),
    };
    if let Some(extra) = positional.next() {
        return Err(format!("unexpected argument {extra}"));
    }
    if username.is_some() || notes.is_some() || force {
        return Err("--username, --notes and --force only apply to add".into());
    }
    if field.is_some() {
        return Err("--field only applies to get".into());
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
            if store.get(&name).is_some() && !force {
                return Err(format!("{name} already exists; pass --force to replace it"));
            }
            let secret = read_secret(&name)?;
            store.insert(
                name,
                Entry {
                    secret,
                    username,
                    notes,
                },
            );
            save(&store, &passphrase)?;
        }
        Command::Get { name, field } => {
            let (store, _) = open(&path)?;
            let entry = store
                .get(&name)
                .ok_or_else(|| format!("no entry named {name}"))?;
            let value = match field {
                Field::Secret => Some(&entry.secret),
                Field::Username => entry.username.as_ref(),
                Field::Notes => entry.notes.as_ref(),
            }
            .ok_or_else(|| format!("{name} has no value for that field"))?;
            print_value(value)?;
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

fn read_secret(name: &str) -> Result<String> {
    let secret = if io::stdin().is_terminal() {
        let first = prompt(&format!("Secret for {name}: "))?;
        if prompt("Repeat it: ")? != first {
            return Err("the secrets did not match".into());
        }
        first
    } else {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| format!("could not read the secret from stdin: {e}"))?;
        strip_newline(input)
    };
    if secret.is_empty() {
        return Err("the secret cannot be empty".into());
    }
    Ok(secret)
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
            "add x --force=yes",
            "list --verbose",
            "list --store",
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?} parsed");
        }
        // The store text cannot hold an entry with no name.
        for command in ["add", "get", "rm"] {
            let argv = vec![command.to_string(), String::new()];
            assert!(parse(argv).is_err(), "{command} with an empty name parsed");
        }
    }

    #[test]
    fn strips_exactly_one_newline() {
        assert_eq!(strip_newline("a\n".into()), "a");
        assert_eq!(strip_newline("a\r\n".into()), "a");
        assert_eq!(strip_newline("a\n\n".into()), "a\n");
        assert_eq!(strip_newline("a".into()), "a");
    }
}
