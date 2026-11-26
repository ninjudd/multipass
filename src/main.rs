mod store;

use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use age::secrecy::{ExposeSecret, SecretString};
use clap::{Parser, Subcommand, ValueEnum};
use store::{Entry, Store};

/// A small single-user password manager: one passphrase, one age-encrypted file.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The store file. Defaults to ~/.multipass/store.age.
    #[arg(long, global = true, env = "MULTIPASS_STORE")]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an empty store protected by a new passphrase.
    Init,
    /// Add an entry. The secret is read from stdin when it is piped,
    /// and from a hidden prompt otherwise.
    Add {
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Replace the entry if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Print one field of an entry, by default its secret.
    Get {
        name: String,
        #[arg(long, value_enum, default_value_t = Field::Secret)]
        field: Field,
    },
    /// List entry names, one per line.
    List,
    /// Remove an entry.
    Rm { name: String },
    /// Change the store's passphrase.
    Passwd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Field {
    Secret,
    Username,
    Notes,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("multipass: {message}");
            ExitCode::FAILURE
        }
    }
}

type Result<T> = std::result::Result<T, String>;

fn run(cli: Cli) -> Result<()> {
    let path = match cli.store {
        Some(path) => path,
        None => default_store_path()?,
    };

    match cli.command {
        Command::Init => {
            if path.exists() {
                return Err(format!("a store already exists at {}", path.display()));
            }
            let passphrase = new_passphrase()?;
            Store::new()
                .save(&path, &passphrase, None)
                .map_err(|e| e.to_string())?;
            eprintln!("Created {}", path.display());
        }
        Command::Add {
            name,
            username,
            notes,
            force,
        } => {
            let passphrase = passphrase("Passphrase: ")?;
            let mut store = Store::load(&path, &passphrase).map_err(|e| e.to_string())?;
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
            store
                .save(&path, &passphrase, None)
                .map_err(|e| e.to_string())?;
        }
        Command::Get { name, field } => {
            let store = open(&path)?;
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
            let store = open(&path)?;
            for name in store.names() {
                println!("{name}");
            }
        }
        Command::Rm { name } => {
            let passphrase = passphrase("Passphrase: ")?;
            let mut store = Store::load(&path, &passphrase).map_err(|e| e.to_string())?;
            store
                .remove(&name)
                .ok_or_else(|| format!("no entry named {name}"))?;
            store
                .save(&path, &passphrase, None)
                .map_err(|e| e.to_string())?;
        }
        Command::Passwd => {
            let store = open(&path)?;
            let passphrase = new_passphrase()?;
            store
                .save(&path, &passphrase, None)
                .map_err(|e| e.to_string())?;
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

fn open(path: &std::path::Path) -> Result<Store> {
    let passphrase = passphrase("Passphrase: ")?;
    Store::load(path, &passphrase).map_err(|e| e.to_string())
}

/// Prompts on the terminal, never on stdin, so stdin stays free for secrets.
fn passphrase(prompt: &str) -> Result<SecretString> {
    rpassword::prompt_password(prompt)
        .map(SecretString::from)
        .map_err(|e| format!("could not read the passphrase: {e}"))
}

fn new_passphrase() -> Result<SecretString> {
    let first = passphrase("New passphrase: ")?;
    if first.expose_secret().is_empty() {
        return Err("the passphrase cannot be empty".into());
    }
    let second = passphrase("Repeat it: ")?;
    if first.expose_secret() != second.expose_secret() {
        return Err("the passphrases did not match".into());
    }
    Ok(first)
}

fn read_secret(name: &str) -> Result<String> {
    let secret = if io::stdin().is_terminal() {
        let first = rpassword::prompt_password(format!("Secret for {name}: "))
            .map_err(|e| format!("could not read the secret: {e}"))?;
        let second = rpassword::prompt_password("Repeat it: ")
            .map_err(|e| format!("could not read the secret: {e}"))?;
        if first != second {
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
