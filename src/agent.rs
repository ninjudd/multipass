//! Session unlock: a background agent that holds the vault key between
//! commands, so only the first command after it starts asks for the
//! passphrase.
//!
//! A command that had to ask for the passphrase starts `multipass __agent`
//! as its own child and hands it the vault key over the child's stdin, never
//! over a socket. The agent then serves one entry per request on a Unix
//! socket in a 0700 directory, and only after Touch ID or an Apple Watch
//! approves that one request, on a sheet that names the entry. Declining
//! ends the session. So a program running as you cannot read or change an
//! entry without a person at the Mac, and the agent never sends the key.
//!
//! The agent ends, writing a note that says why, when the key reaches its
//! deadline, on `multipass lock`, when a request is declined, when a
//! rotation elsewhere leaves it holding an old key, and when its executable
//! changes on disk. The next command then asks for the passphrase and says
//! why.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::sha256;
use crate::store::{self, Cutoffs, Store};
use crate::sys;
use crate::touch_id::{Approval, TouchId};
use crate::vault::{self, Vault};

/// The hidden command the agent runs, kept out of `--help`.
pub const COMMAND: &str = "__agent";

/// How long a command waits for a new agent to say `ready`.
const START_WAIT: Duration = Duration::from_secs(2);
/// How long a client may take to send each request.
const REQUEST_WAIT: Duration = Duration::from_secs(2);
/// How long an `edit` waits for its `save`, while the command asks you for
/// the new value.
const SAVE_WAIT: Duration = Duration::from_secs(5 * 60);
/// How long a sheet waits for a touch before it counts as declined.
pub const APPROVAL_WAIT: Duration = Duration::from_secs(60);
/// How long a client waits for a reply: the sheet's wait and some slack.
const REPLY_WAIT: Duration = Duration::from_secs(75);
/// The largest counted body either side accepts, far beyond any store.
const MAX_BODY: usize = 64 << 20;
/// How long the agent's accept loop sleeps between checks that it should
/// end. An idle agent runs for up to 21 days, so it wakes only once a second.
const POLL: Duration = Duration::from_secs(1);
/// The longest entry name a sheet shows.
const REASON_NAME_CHARS: usize = 60;

/// Asks a person to approve one request. The agent uses Touch ID; tests
/// use a fake.
pub trait Approver: Send + Sync + 'static {
    fn approve(&self, reason: &str) -> Approval;
}

/// Approval through Touch ID or an Apple Watch on this Mac.
pub struct TouchIdApprover;

impl Approver for TouchIdApprover {
    fn approve(&self, reason: &str) -> Approval {
        TouchId::approve(reason, APPROVAL_WAIT)
    }
}

/// Whether commands may use an agent: not with `MULTIPASS_NO_AGENT` set,
/// and not over SSH, where nobody can touch the Mac's sensor.
pub fn enabled(no_agent: Option<&str>, ssh_connection: Option<&str>) -> bool {
    let set = |v: Option<&str>| v.is_some_and(|v| !v.is_empty());
    cfg!(target_os = "macos") && !set(no_agent) && !set(ssh_connection)
}

/// Where one store's agent listens and leaves its end note.
#[derive(Debug, Clone)]
pub struct Paths {
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub note: PathBuf,
}

impl Paths {
    /// The paths for the store package at `package`, in `dir`, which is
    /// `~/.multipass/agent` in the CLI. Each store gets its own agent,
    /// named by a hash of its canonical path, which is public.
    pub fn new(dir: &Path, package: &Path) -> Paths {
        let canonical = package
            .canonicalize()
            .unwrap_or_else(|_| package.to_path_buf());
        let digest = sha256::hex_digest(canonical.as_os_str().as_encoded_bytes());
        let hash = &digest[..16];
        Paths {
            dir: dir.to_path_buf(),
            socket: dir.join(format!("{hash}.sock")),
            note: dir.join(format!("{hash}.ended")),
        }
    }
}

/// Fails unless `dir` is a directory, not a symbolic link, that belongs to
/// this user and has mode 0700, so no other user can reach the socket.
pub fn check_dir(dir: &Path) -> Result<(), String> {
    let refuse = || {
        format!(
            "not using the session agent: {} must be a directory of yours with mode 0700",
            dir.display()
        )
    };
    let meta = fs::symlink_metadata(dir).map_err(|_| refuse())?;
    if meta.is_dir() && meta.uid() == sys::uid() && meta.mode() & 0o777 == 0o700 {
        Ok(())
    } else {
        Err(refuse())
    }
}

/// Why a session ended, as the end note records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    Expired,
    Declined,
    Changed,
    Locked,
    Updated,
}

impl Ended {
    const ALL: [Ended; 5] = [
        Ended::Expired,
        Ended::Declined,
        Ended::Changed,
        Ended::Locked,
        Ended::Updated,
    ];

    fn word(self) -> &'static str {
        match self {
            Ended::Expired => "expired",
            Ended::Declined => "declined",
            Ended::Changed => "changed",
            Ended::Locked => "locked",
            Ended::Updated => "updated",
        }
    }

    /// What the next prompt says about it.
    pub fn reason(self) -> &'static str {
        match self {
            Ended::Expired => "the vault key expired",
            Ended::Declined => "you declined a request",
            Ended::Changed => "the vault key changed",
            Ended::Locked => "locked by multipass lock",
            Ended::Updated => "multipass was updated",
        }
    }
}

/// The end note: why the last agent for this store ended, and when, in
/// Unix seconds. `None` when there is no note or it does not parse.
pub fn end_note(paths: &Paths) -> Option<(Ended, u64)> {
    let text = fs::read_to_string(&paths.note).ok()?;
    let (word, at) = text.trim_end().split_once(' ')?;
    let ended = Ended::ALL.into_iter().find(|e| e.word() == word)?;
    Some((ended, at.parse().ok()?))
}

/// What a command found when it tried the store's agent before prompting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tried {
    /// It did not ask, as `passwd` and `rekey` never do.
    NotAsked,
    /// No agent answered.
    NoAgent,
    /// An agent answered from another executable than this command's.
    Updated,
    /// The agent answered, but neither Touch ID nor a watch could approve.
    Unavailable,
    /// The agent's key no longer opens the store, and it ended.
    Stale,
}

/// Why the passphrase is being asked for. Only a session that ended has a
/// reason: the end note's, or `the session ended` when a socket is left
/// with no agent behind it and no note, as after a restart. A command that
/// did not ask a running agent, or whose agent could not get a touch, gives
/// none.
pub fn prompt_reason(paths: &Paths, tried: Tried) -> Option<&'static str> {
    match tried {
        Tried::NotAsked | Tried::Unavailable => None,
        Tried::Updated => Some(Ended::Updated.reason()),
        Tried::NoAgent | Tried::Stale => match end_note(paths) {
            Some((ended, _)) => Some(ended.reason()),
            None if paths.socket.exists() => Some("the session ended"),
            None => None,
        },
    }
}

/// The passphrase prompt, with the reason it asks, if there is one.
pub fn prompt_text(reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("Passphrase ({reason}): "),
        None => "Passphrase: ".into(),
    }
}

/// What identifies an executable file across an upgrade: a rename over it
/// gives a new inode, and any write or rename sets a new change time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExeId {
    dev: u64,
    ino: u64,
    size: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl ExeId {
    pub fn of(path: &Path) -> io::Result<ExeId> {
        let meta = fs::metadata(path)?;
        Ok(ExeId {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        })
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Reads one `\n`-terminated line of at most 64 bytes, without the `\n`.
fn read_line(r: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        r.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        if line.len() == 64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        line.push(byte[0]);
    }
    String::from_utf8(line).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not ASCII"))
}

/// Reads the `n` bytes a line announced.
fn read_body(r: &mut impl Read, n: &str) -> io::Result<Vec<u8>> {
    let n: usize = n
        .parse()
        .ok()
        .filter(|&n| n <= MAX_BODY)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?;
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(body)
}

fn read_text(r: &mut impl Read, n: &str) -> io::Result<String> {
    String::from_utf8(read_body(r, n)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))
}

/// Writes `word <n>\n` and then the `n` bytes of `body`.
fn write_counted(w: &mut impl Write, word: &str, body: &[u8]) -> io::Result<()> {
    w.write_all(format!("{word} {}\n", body.len()).as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// The message a command writes to a new agent's stdin: the key's deadline
/// in Unix seconds and the keys, as `Session::agent_keys` gives them.
pub fn start_message(deadline: u64, keys: &str) -> Vec<u8> {
    let mut message = format!("start {deadline} {}\n", keys.len()).into_bytes();
    message.extend_from_slice(keys.as_bytes());
    message
}

/// Reads the start message, refusing a short key, a missing count, and any
/// bytes after the key.
fn read_start(r: &mut impl Read) -> io::Result<(u64, String)> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "bad start message");
    let line = read_line(r)?;
    let mut words = line.split(' ');
    let (Some("start"), Some(deadline), Some(n), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        return Err(bad());
    };
    let deadline = deadline.parse().map_err(|_| bad())?;
    let keys = read_text(r, n)?;
    let mut rest = [0u8; 1];
    if r.read(&mut rest)? != 0 {
        return Err(bad());
    }
    Ok((deadline, keys))
}

/// One request the agent needs approval for.
enum Request {
    Read(String),
    Edit(String),
    List,
}

impl Request {
    /// What the sheet says: "multipass is trying to <reason>".
    fn reason(&self) -> String {
        let short = |name: &str| -> String {
            store::escape(name)
                .chars()
                .take(REASON_NAME_CHARS)
                .collect()
        };
        match self {
            Request::Read(name) => format!("read {}", short(name)),
            Request::Edit(name) => format!("change {}", short(name)),
            Request::List => "list your entries".into(),
        }
    }
}

/// The agent: the keys it holds and what it needs to serve and end.
pub struct Agent<A: Approver> {
    /// One open or save at a time, from any connection.
    vault: Mutex<Vault>,
    paths: Paths,
    /// The keys' text, wiped when the agent ends.
    keys: Mutex<String>,
    /// When the vault key expires, in Unix seconds.
    deadline: u64,
    approver: A,
    /// The agent's executable and its identity when the agent started.
    exe: Option<(PathBuf, ExeId)>,
    /// Set by the first `end`: the session is over, and no request is served.
    ending: AtomicBool,
    /// Set once the handler that ended the session has written its reply, so
    /// `serve` returns, and the process exits, only after that reply is out.
    stopped: AtomicBool,
    /// Held while a sheet shows, so there is one at a time.
    one_sheet: Mutex<()>,
}

/// Runs the `__agent` command: leaves the terminal's session, protects its
/// memory, reads the start message, and serves until the session ends.
pub fn run_agent(vault: Vault, paths: Paths) -> Result<(), String> {
    sys::new_session().map_err(|e| e.to_string())?;
    sys::deny_debuggers().map_err(|e| e.to_string())?;
    sys::no_core_files().map_err(|e| e.to_string())?;
    if !TouchId::available() {
        return Err("neither Touch ID nor an Apple Watch can approve requests".into());
    }
    // Read the start message without std's stdin buffer, which would keep an
    // unpinned copy of the keys for the agent's whole life.
    let mut stdin = fs::File::open("/dev/stdin").map_err(|e| e.to_string())?;
    let (deadline, keys) = read_start(&mut stdin).map_err(|e| e.to_string())?;
    drop(stdin);
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let id = ExeId::of(&exe).map_err(|e| e.to_string())?;
    let agent = Arc::new(Agent::new(
        vault,
        paths,
        keys,
        deadline,
        TouchIdApprover,
        Some((exe, id)),
    ));
    let listener = agent.bind()?;
    // The command that started the agent stops waiting for `ready` after 2
    // seconds, so a failed write means only that nobody is listening; the
    // agent serves either way.
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(b"ready\n").and_then(|()| stdout.flush());
    drop(stdout);
    agent.serve(listener);
    Ok(())
}

impl<A: Approver> Agent<A> {
    pub fn new(
        vault: Vault,
        paths: Paths,
        keys: String,
        deadline: u64,
        approver: A,
        exe: Option<(PathBuf, ExeId)>,
    ) -> Agent<A> {
        // Best effort: an agent that cannot pin the page still serves.
        let _ = sys::lock_in_memory(keys.as_bytes());
        Agent {
            vault: Mutex::new(vault),
            paths,
            keys: Mutex::new(keys),
            deadline,
            approver,
            exe,
            ending: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            one_sheet: Mutex::new(()),
        }
    }

    /// Checks that the keys open the store and that no agent already serves
    /// it, then binds the socket and removes the last end note.
    pub fn bind(&self) -> Result<UnixListener, String> {
        if now_ms() / 1000 >= self.deadline {
            return Err(vault::Error::Stale.to_string());
        }
        self.open().map_err(|e| e.to_string())?;
        store::create_private_dir(&self.paths.dir).map_err(|e| e.to_string())?;
        check_dir(&self.paths.dir)?;
        if self.paths.socket.exists() {
            if UnixStream::connect(&self.paths.socket).is_ok() {
                return Err("another agent already serves this store".into());
            }
            fs::remove_file(&self.paths.socket).map_err(|e| e.to_string())?;
        }
        let listener = UnixListener::bind(&self.paths.socket).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&self.paths.note);
        Ok(listener)
    }

    /// Answers connections, each on its own thread, until the session ends
    /// and the handler that ended it has replied.
    pub fn serve(self: &Arc<Self>, listener: UnixListener) {
        if listener.set_nonblocking(true).is_err() {
            self.end(Ended::Locked);
            return;
        }
        while !self.stopped.load(Ordering::SeqCst) {
            if now_ms() / 1000 >= self.deadline {
                self.end(Ended::Expired);
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let agent = Arc::clone(self);
                    std::thread::spawn(move || agent.handle(stream));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
                Err(_) => std::thread::sleep(POLL),
            }
        }
    }

    /// Writes the end note, removes the socket, and wipes the keys. Only
    /// the first call does anything.
    pub fn end(&self, why: Ended) {
        if self.ending.swap(true, Ordering::SeqCst) {
            return;
        }
        let note = format!("{} {}\n", why.word(), now_ms() / 1000);
        let _ = fs::write(&self.paths.note, note);
        let _ = fs::remove_file(&self.paths.socket);
        let mut keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        sys::wipe_string(&mut keys);
    }

    fn open(&self) -> Result<vault::Session, vault::Error> {
        let keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        let vault = self.vault.lock().unwrap_or_else(|p| p.into_inner());
        vault.open_with_keys(&keys, now_ms())
    }

    /// Answers one connection, then lets `serve` return when the answer
    /// ended the session.
    fn handle(&self, stream: UnixStream) {
        self.handle_one(stream);
        if self.ending.load(Ordering::SeqCst) {
            self.stopped.store(true, Ordering::SeqCst);
        }
    }

    fn handle_one(&self, mut stream: UnixStream) {
        if sys::peer_uid(stream.as_raw_fd()).ok() != Some(sys::uid()) {
            return;
        }
        // On macOS an accepted socket inherits the listener's non-blocking
        // mode, so reads would fail whenever the client is slower than this.
        if stream.set_nonblocking(false).is_err()
            || stream.set_read_timeout(Some(REQUEST_WAIT)).is_err()
        {
            return;
        }
        let Ok(line) = read_line(&mut stream) else {
            return;
        };
        let words: Vec<&str> = line.split(' ').collect();
        let request = match words.as_slice() {
            ["status"] => {
                if !self.ending.load(Ordering::SeqCst) {
                    let _ = stream.write_all(format!("unlocked {}\n", self.deadline).as_bytes());
                }
                return;
            }
            ["lock"] => {
                self.end(Ended::Locked);
                let _ = stream.write_all(b"ok\n");
                return;
            }
            ["list"] => Request::List,
            ["read", n] => match read_text(&mut stream, n) {
                Ok(name) => Request::Read(name),
                Err(_) => return,
            },
            ["edit", n] => match read_text(&mut stream, n) {
                Ok(name) => Request::Edit(name),
                Err(_) => return,
            },
            _ => return,
        };
        let _ = self.answer(request, &mut stream);
    }

    /// Ends the session when something has made this agent unfit to serve:
    /// it has ended already, its executable changed, or its key expired.
    fn unfit(&self) -> bool {
        if self.ending.load(Ordering::SeqCst) {
            return true;
        }
        if let Some((path, id)) = &self.exe {
            if ExeId::of(path).ok().as_ref() != Some(id) {
                self.end(Ended::Updated);
                return true;
            }
        }
        if now_ms() / 1000 >= self.deadline {
            self.end(Ended::Expired);
            return true;
        }
        false
    }

    /// Opens the store for an approved request, replying and ending the
    /// session when a rotation elsewhere has left this agent's key behind.
    /// When an older Mac has saved to the old single-file store since its
    /// move record, it replies `unavailable` instead, so the command prompts
    /// and the prompt merges that change.
    fn open_for(&self, stream: &mut UnixStream) -> io::Result<Option<vault::Session>> {
        match self.open() {
            Ok(session) => {
                let vault = self.vault.lock().unwrap_or_else(|p| p.into_inner());
                if session.old_file_changed(&vault) {
                    stream.write_all(b"unavailable\n")?;
                    return Ok(None);
                }
                Ok(Some(session))
            }
            Err(vault::Error::Stale) => {
                self.end(Ended::Changed);
                stream.write_all(b"stale\n")?;
                Ok(None)
            }
            Err(e) => {
                write_counted(stream, "failed", e.to_string().as_bytes())?;
                Ok(None)
            }
        }
    }

    fn answer(&self, request: Request, stream: &mut UnixStream) -> io::Result<()> {
        if self.unfit() {
            return stream.write_all(b"stale\n");
        }
        let approval = {
            let _sheet = self.one_sheet.lock().unwrap_or_else(|p| p.into_inner());
            if self.unfit() {
                return stream.write_all(b"stale\n");
            }
            self.approver.approve(&request.reason())
        };
        match approval {
            Approval::Approved => {}
            Approval::Denied => {
                self.end(Ended::Declined);
                stream.write_all(b"denied\n")?;
                return Ok(());
            }
            Approval::Unavailable => return stream.write_all(b"unavailable\n"),
        }
        if self.unfit() {
            return stream.write_all(b"stale\n");
        }
        let Some(session) = self.open_for(stream)? else {
            return Ok(());
        };
        let now = now_ms();
        match request {
            Request::List => {
                let mut names = String::new();
                for name in session.store.names() {
                    names.push_str(&store::escape(name));
                    names.push('\n');
                }
                write_counted(stream, "ok", names.as_bytes())
            }
            Request::Read(name) => send_version(stream, &session.store, &name, now),
            Request::Edit(name) => {
                send_version(stream, &session.store, &name, now)?;
                drop(session);
                self.save(stream, &name)
            }
        }
    }

    /// Waits for the `save` that follows an `edit` of `name`, refuses one
    /// that touches any other entry, and saves the entry into the store as
    /// it is now, merged again, with a fresh stamp.
    fn save(&self, stream: &mut UnixStream, name: &str) -> io::Result<()> {
        stream.set_read_timeout(Some(SAVE_WAIT))?;
        let line = read_line(stream)?;
        let Some(n) = line.strip_prefix("save ") else {
            return stream.write_all(b"refused\n");
        };
        let mut text = read_text(stream, n)?;
        let sent = Store::from_text(&text);
        sys::wipe_string(&mut text);
        let Ok(sent) = sent else {
            return stream.write_all(b"refused\n");
        };
        if sent.all_names().any(|other| other != name) {
            return stream.write_all(b"refused\n");
        }
        if self.unfit() {
            return stream.write_all(b"stale\n");
        }
        let Some(mut session) = self.open_for(stream)? else {
            return Ok(());
        };
        let now = now_ms();
        let stamp = session.store.stamp(now);
        match sent.get(name) {
            Some(entry) => {
                session.store.insert(name, entry.clone(), stamp);
            }
            None => {
                session.store.remove(name, stamp);
            }
        }
        let vault = self.vault.lock().unwrap_or_else(|p| p.into_inner());
        match session.save(&vault, now) {
            Ok(()) => stream.write_all(b"saved\n"),
            Err(vault::Error::Io(e)) => {
                let message = format!("could not write to {}: {e}", vault.path().display());
                write_counted(stream, "failed", message.as_bytes())
            }
            Err(e) => write_counted(stream, "failed", e.to_string().as_bytes()),
        }
    }
}

/// Replies with store text holding only `name`'s version, or `missing`.
fn send_version(stream: &mut UnixStream, store: &Store, name: &str, now: u64) -> io::Result<()> {
    let only = store.only(name);
    if only.all_names().next().is_none() {
        return stream.write_all(b"missing\n");
    }
    let mut text = only.to_text(Cutoffs::at(now)).into_bytes();
    let written = write_counted(stream, "ok", &text);
    sys::wipe(&mut text);
    written
}

/// An agent's answer to `read`, `list`, or `edit`.
#[derive(Debug)]
pub enum Answer {
    /// Store text holding only the requested entry, for `read` and `edit`.
    Entry(Store),
    /// The entry names, for `list`.
    Names(Vec<String>),
    Missing,
    Denied,
    Unavailable,
    Stale,
}

/// A connection to a store's agent that passed the checks.
pub struct Client {
    stream: UnixStream,
}

/// An `edit` the agent approved, waiting for the changed entry.
pub struct Editing {
    stream: UnixStream,
}

/// Which checks `connect` makes of the agent at the other end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// It runs as this user from this command's own executable, as a
    /// request that hands over or changes an entry needs.
    SameBinary,
    /// It runs as this user. Enough for `status` and `lock`, which send
    /// nothing and only learn or end the session, whichever multipass
    /// binary started it.
    SameUser,
}

/// Connects to the store's agent. `Err(Tried::NoAgent)` when no agent
/// answers or the one that does runs as another user, and, with
/// `Peer::SameBinary`, `Err(Tried::Updated)` when it runs from another
/// executable than this command; either way the command asks for the
/// passphrase. A directory that fails `check_dir` is named on stderr and
/// counts as no agent.
pub fn connect(paths: &Paths, peer: Peer) -> Result<Client, Tried> {
    if !paths.dir.exists() {
        return Err(Tried::NoAgent);
    }
    if let Err(refused) = check_dir(&paths.dir) {
        eprintln!("multipass: {refused}");
        return Err(Tried::NoAgent);
    }
    let stream = UnixStream::connect(&paths.socket).map_err(|_| Tried::NoAgent)?;
    let fd = stream.as_raw_fd();
    if sys::peer_uid(fd).ok() != Some(sys::uid()) {
        return Err(Tried::NoAgent);
    }
    if peer == Peer::SameBinary {
        let theirs = sys::peer_pid(fd)
            .and_then(sys::pid_path)
            .and_then(|path| ExeId::of(&path));
        let ours = std::env::current_exe().and_then(|path| ExeId::of(&path));
        match (theirs, ours) {
            (Ok(theirs), Ok(ours)) if theirs == ours => {}
            _ => return Err(Tried::Updated),
        }
    }
    if stream.set_read_timeout(Some(REPLY_WAIT)).is_err()
        || stream.set_write_timeout(Some(REQUEST_WAIT)).is_err()
    {
        return Err(Tried::NoAgent);
    }
    Ok(Client { stream })
}

fn protocol_error() -> String {
    "the session agent sent a reply this multipass does not understand".into()
}

/// Reads a reply to `read`, `list`, or `edit`.
fn read_answer(stream: &mut UnixStream, names: bool) -> Result<Answer, String> {
    let line = read_line(stream).map_err(|_| protocol_error())?;
    let words: Vec<&str> = line.split(' ').collect();
    match words.as_slice() {
        ["ok", n] => {
            let mut text = read_text(stream, n).map_err(|_| protocol_error())?;
            let answer = if names {
                text.lines()
                    .map(store::unescape)
                    .collect::<Option<Vec<String>>>()
                    .map(Answer::Names)
                    .ok_or_else(protocol_error)
            } else {
                Store::from_text(&text)
                    .map(Answer::Entry)
                    .map_err(|_| protocol_error())
            };
            sys::wipe_string(&mut text);
            answer
        }
        ["missing"] => Ok(Answer::Missing),
        ["denied"] => Ok(Answer::Denied),
        ["unavailable"] => Ok(Answer::Unavailable),
        ["stale"] => Ok(Answer::Stale),
        ["failed", n] => Err(read_text(stream, n).map_err(|_| protocol_error())?),
        _ => Err(protocol_error()),
    }
}

impl Client {
    fn ask(&mut self, word: &str, name: &str) -> Result<Answer, String> {
        write_counted(&mut self.stream, word, name.as_bytes()).map_err(|_| protocol_error())?;
        read_answer(&mut self.stream, false)
    }

    /// Asks for one entry, live or removed, with its history.
    pub fn read(mut self, name: &str) -> Result<Answer, String> {
        self.ask("read", name)
    }

    /// Asks for the live entry names.
    pub fn list(mut self) -> Result<Answer, String> {
        self.stream
            .write_all(b"list\n")
            .map_err(|_| protocol_error())?;
        read_answer(&mut self.stream, true)
    }

    /// Asks to change one entry. On `Entry` or `Missing`, the agent waits
    /// for `Editing::save` on the same connection.
    pub fn edit(mut self, name: &str) -> Result<(Answer, Editing), String> {
        let answer = self.ask("edit", name)?;
        Ok((
            answer,
            Editing {
                stream: self.stream,
            },
        ))
    }

    /// The deadline the agent serves until, in Unix seconds.
    pub fn status(mut self) -> Option<u64> {
        self.stream.write_all(b"status\n").ok()?;
        let line = read_line(&mut self.stream).ok()?;
        line.strip_prefix("unlocked ")?.parse().ok()
    }

    /// Ends the session. True when the agent confirmed.
    pub fn lock(mut self) -> bool {
        self.stream.write_all(b"lock\n").is_ok()
            && read_line(&mut self.stream).is_ok_and(|line| line == "ok")
    }
}

impl Editing {
    /// Sends the changed entry: `store` holds it, or holds nothing, or a
    /// tombstone for it, to remove it.
    pub fn save(mut self, store: &Store, now: u64) -> Result<(), String> {
        let mut text = store.to_text(Cutoffs::at(now)).into_bytes();
        let sent = write_counted(&mut self.stream, "save", &text);
        sys::wipe(&mut text);
        sent.map_err(|_| protocol_error())?;
        let line = read_line(&mut self.stream).map_err(|_| protocol_error())?;
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            ["saved"] => Ok(()),
            ["refused"] => Err("the session agent refused the change".into()),
            ["unavailable"] => {
                Err("an older multipass changed the store meanwhile; run the command again".into())
            }
            ["stale"] => Err(format!(
                "{}; run the command again",
                Ended::Changed.reason()
            )),
            ["failed", n] => Err(read_text(&mut self.stream, n).map_err(|_| protocol_error())?),
            _ => Err(protocol_error()),
        }
    }
}

/// Starts an agent for the store at `store`, holding `keys` until
/// `deadline`, and waits briefly for it to say `ready`. A failed start
/// costs nothing but the next prompt, so it reports nothing.
pub fn start(store: &Path, keys: &str, deadline: u64) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Ok(mut child) = Command::new(exe)
        .arg("--store")
        .arg(store)
        .arg(COMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let mut message = start_message(deadline, keys);
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&message);
    }
    sys::wipe(&mut message);
    let Some(stdout) = child.stdout.take() else {
        return;
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send(line);
    });
    let _ = receiver.recv_timeout(START_WAIT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Entry;
    use std::sync::atomic::AtomicUsize;

    const FAST: u8 = 10;

    fn temp(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        // A Unix socket path must fit in 104 bytes, which the system
        // temporary directory on macOS leaves little room for.
        let dir = PathBuf::from("/tmp").join(format!(
            "mp-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fake approver that answers from a script and records each reason.
    #[derive(Clone)]
    struct Fake {
        answers: Arc<Mutex<Vec<Approval>>>,
        reasons: Arc<Mutex<Vec<String>>>,
    }

    impl Fake {
        fn always(approval: Approval) -> Fake {
            Fake {
                answers: Arc::new(Mutex::new(vec![approval; 64])),
                reasons: Arc::default(),
            }
        }

        fn reasons(&self) -> Vec<String> {
            self.reasons.lock().unwrap().clone()
        }
    }

    impl Approver for Fake {
        fn approve(&self, reason: &str) -> Approval {
            self.reasons.lock().unwrap().push(reason.to_string());
            self.answers
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Approval::Denied)
        }
    }

    fn entry(secret: &str) -> Entry {
        Entry {
            secret: Some(secret.into()),
            username: None,
            notes: None,
            otp: None,
        }
    }

    /// A package of three entries in a temporary directory, the keys an
    /// agent would hold for it, and the agent paths beside it.
    struct Setup {
        root: PathBuf,
        package: PathBuf,
        keys: String,
        deadline: u64,
        paths: Paths,
    }

    fn setup(name: &str) -> Setup {
        let root = temp(name);
        let package = root.join("store.multipass");
        let vault = Vault::new(&package, FAST);
        let now = now_ms();
        vault.init("pw", now).unwrap();
        let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
        let mut session = vault.open(&mut ask, now).unwrap();
        for (i, name) in ["a", "b", "c"].into_iter().enumerate() {
            let stamp = session.store.stamp(now + i as u64);
            session
                .store
                .insert(name, entry(&format!("{name}-secret")), stamp);
        }
        session.save(&vault, now).unwrap();
        let agent_dir = root.join("agent");
        store::create_private_dir(&agent_dir).unwrap();
        Setup {
            paths: Paths::new(&agent_dir, &package),
            keys: session.agent_keys(),
            deadline: session.session_deadline(),
            root,
            package,
        }
    }

    fn agent(s: &Setup, approver: Fake) -> Arc<Agent<Fake>> {
        Arc::new(Agent::new(
            Vault::new(&s.package, FAST),
            s.paths.clone(),
            s.keys.clone(),
            s.deadline,
            approver,
            None,
        ))
    }

    /// Binds the agent and serves it on a thread, as `run_agent` does.
    fn serving(agent: &Arc<Agent<Fake>>) {
        let listener = agent.bind().unwrap();
        let agent = Arc::clone(agent);
        std::thread::spawn(move || agent.serve(listener));
    }

    /// A client without the executable check, which an agent serving from
    /// the test harness's own thread would fail only by accident.
    fn client(s: &Setup) -> Client {
        let stream = UnixStream::connect(&s.paths.socket).unwrap();
        stream.set_read_timeout(Some(REPLY_WAIT)).unwrap();
        Client { stream }
    }

    /// Ends the session and stops `serve`, as a handler that ended it would.
    fn finish(agent: &Arc<Agent<Fake>>) {
        agent.end(Ended::Locked);
        agent.stopped.store(true, Ordering::SeqCst);
    }

    /// `serve` keeps running after `end` until a handler has replied and set
    /// `stopped`. Catches a `serve` that watches the flag `end` sets, which
    /// lets the process exit before the ending reply is written.
    #[test]
    fn ending_alone_does_not_stop_serve() {
        let s = setup("end-alone");
        let agent = agent(&s, Fake::always(Approval::Approved));
        let listener = agent.bind().unwrap();
        let serving = {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || agent.serve(listener))
        };
        agent.end(Ended::Locked);
        std::thread::sleep(POLL * 2);
        assert!(!serving.is_finished(), "serve returned before any reply");
        agent.stopped.store(true, Ordering::SeqCst);
        serving.join().unwrap();
        fs::remove_dir_all(&s.root).unwrap();
    }

    fn wait_until(mut done: impl FnMut() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out");
    }

    #[test]
    fn the_start_message_round_trips_and_refuses_damage() {
        let message = start_message(1_766_000_000, "multipass-key 1\nkey abc\n");
        let (deadline, keys) = read_start(&mut message.as_slice()).unwrap();
        assert_eq!(deadline, 1_766_000_000);
        assert_eq!(keys, "multipass-key 1\nkey abc\n");

        let short = &message[..message.len() - 1];
        assert!(read_start(&mut &short[..]).is_err());
        let mut trailing = message.clone();
        trailing.push(b'x');
        assert!(read_start(&mut trailing.as_slice()).is_err());
        assert!(read_start(&mut &b"start 1766000000\nabc"[..]).is_err());
    }

    #[test]
    fn each_request_asks_once_and_names_its_entry() {
        let s = setup("reasons");
        let fake = Fake::always(Approval::Approved);
        let agent = agent(&s, fake.clone());
        serving(&agent);

        let Answer::Entry(one) = client(&s).read("b").unwrap() else {
            panic!("expected an entry");
        };
        assert_eq!(one.names().collect::<Vec<_>>(), ["b"]);
        assert_eq!(one.get("b").unwrap().secret.as_deref(), Some("b-secret"));
        client(&s).read("b").unwrap();
        let Answer::Names(names) = client(&s).list().unwrap() else {
            panic!("expected names");
        };
        assert_eq!(names, ["a", "b", "c"]);
        let (answer, editing) = client(&s).edit("x").unwrap();
        assert!(matches!(answer, Answer::Missing));
        drop(editing);
        assert_eq!(
            fake.reasons(),
            ["read b", "read b", "list your entries", "change x"]
        );
        finish(&agent);
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn a_declined_request_gets_nothing_and_ends_the_session() {
        let s = setup("declined");
        let agent = agent(&s, Fake::always(Approval::Denied));
        serving(&agent);
        let mut stream = UnixStream::connect(&s.paths.socket).unwrap();
        write_counted(&mut stream, "read", b"b").unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"denied\n");
        // The session ended before the reply went out.
        assert!(!s.paths.socket.exists());
        assert_eq!(end_note(&s.paths).map(|n| n.0), Some(Ended::Declined));
        assert_eq!(
            prompt_text(prompt_reason(&s.paths, Tried::NoAgent)),
            "Passphrase (you declined a request): "
        );
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn an_unavailable_sensor_keeps_the_session() {
        let s = setup("unavailable");
        let agent = agent(&s, Fake::always(Approval::Unavailable));
        serving(&agent);
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Unavailable));
        assert_eq!(client(&s).status(), Some(s.deadline));
        finish(&agent);
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn a_save_changes_only_the_entry_it_edited() {
        let s = setup("save");
        let agent = agent(&s, Fake::always(Approval::Approved));
        serving(&agent);
        let vault = Vault::new(&s.package, FAST);
        let read = |name: &str| {
            let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
            vault
                .open(&mut ask, now_ms())
                .unwrap()
                .store
                .get(name)
                .and_then(|e| e.secret.clone())
        };

        // A save that also holds another entry is refused, and changes nothing.
        let (_, editing) = client(&s).edit("b").unwrap();
        let mut both = Store::new();
        both.insert("b", entry("new-b"), now_ms());
        both.insert("c", entry("new-c"), now_ms());
        assert!(editing.save(&both, now_ms()).is_err());
        let (_, editing) = client(&s).edit("b").unwrap();
        let mut other = Store::new();
        other.insert("c", entry("new-c"), now_ms());
        assert!(editing.save(&other, now_ms()).is_err());
        assert_eq!(read("b").as_deref(), Some("b-secret"));
        assert_eq!(read("c").as_deref(), Some("c-secret"));

        // A file another command saves between edit and save survives.
        let (answer, editing) = client(&s).edit("b").unwrap();
        let Answer::Entry(mut one) = answer else {
            panic!("expected b");
        };
        {
            let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
            let mut session = vault.open(&mut ask, now_ms()).unwrap();
            let stamp = session.store.stamp(now_ms());
            session.store.insert("d", entry("d-secret"), stamp);
            session.save(&vault, now_ms()).unwrap();
        }
        let stamp = one.stamp(now_ms());
        one.insert("b", entry("new-b"), stamp);
        editing.save(&one, now_ms()).unwrap();
        assert_eq!(read("b").as_deref(), Some("new-b"));
        assert_eq!(read("d").as_deref(), Some("d-secret"));

        // An empty save removes the entry, leaving a tombstone.
        let (_, editing) = client(&s).edit("a").unwrap();
        editing.save(&Store::new(), now_ms()).unwrap();
        assert_eq!(read("a"), None);
        let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
        let store = vault.open(&mut ask, now_ms()).unwrap().store;
        assert!(store.version("a").is_some_and(|v| v.entry.is_none()));

        // A save with no edit before it is refused.
        let mut stream = UnixStream::connect(&s.paths.socket).unwrap();
        write_counted(
            &mut stream,
            "save",
            Store::new().to_text(Cutoffs::at(0)).as_bytes(),
        )
        .unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty());
        finish(&agent);
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn a_rotation_elsewhere_makes_the_agent_stale() {
        let s = setup("stale");
        let agent = agent(&s, Fake::always(Approval::Approved));
        serving(&agent);
        let vault = Vault::new(&s.package, FAST);
        let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
        let mut session = vault.open(&mut ask, now_ms()).unwrap();
        session.rotate(&vault, now_ms(), None).unwrap();
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Stale));
        wait_until(|| !s.paths.socket.exists());
        assert_eq!(end_note(&s.paths).map(|n| n.0), Some(Ended::Changed));
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn an_agent_past_its_deadline_does_not_start() {
        let s = setup("expired");
        let past = Arc::new(Agent::new(
            Vault::new(&s.package, FAST),
            s.paths.clone(),
            s.keys.clone(),
            now_ms() / 1000 - 1,
            Fake::always(Approval::Approved),
            None,
        ));
        assert!(past.bind().is_err());
        assert!(!s.paths.socket.exists());
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn a_changed_executable_ends_the_session() {
        let s = setup("updated");
        let exe = s.root.join("multipass");
        fs::write(&exe, b"old binary").unwrap();
        let id = ExeId::of(&exe).unwrap();
        let agent = Arc::new(Agent::new(
            Vault::new(&s.package, FAST),
            s.paths.clone(),
            s.keys.clone(),
            s.deadline,
            Fake::always(Approval::Approved),
            Some((exe.clone(), id)),
        ));
        serving(&agent);
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Entry(_)));

        // Rewritten in place: same inode, new size and change time.
        fs::write(&exe, b"new binary, longer").unwrap();
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Stale));
        assert_eq!(end_note(&s.paths).map(|n| n.0), Some(Ended::Updated));

        // Replaced by rename: a new inode.
        let rewritten = s.root.join("multipass.new");
        fs::write(&rewritten, b"old binary").unwrap();
        fs::rename(&rewritten, &exe).unwrap();
        assert_ne!(ExeId::of(&exe).unwrap(), id);
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn lock_ends_the_session_and_status_reports_the_deadline() {
        let s = setup("lock");
        let agent = agent(&s, Fake::always(Approval::Approved));
        serving(&agent);
        assert_eq!(client(&s).status(), Some(s.deadline));
        assert!(client(&s).lock());
        wait_until(|| !s.paths.socket.exists());
        assert_eq!(end_note(&s.paths).map(|n| n.0), Some(Ended::Locked));
        assert!(agent.keys.lock().unwrap().is_empty());
        fs::remove_dir_all(&s.root).unwrap();
    }

    #[test]
    fn the_deadline_is_the_keys_creation_plus_21_days() {
        // A key made five days before the session opens, so a deadline
        // counted from the session's start would land five days late.
        const DAY: u64 = 24 * 60 * 60;
        let root = temp("deadline");
        let vault = Vault::new(root.join("store.multipass"), FAST);
        let made = now_ms() / 1000 - 5 * DAY;
        vault.init("pw", made * 1000).unwrap();
        let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
        let session = vault.open(&mut ask, now_ms()).unwrap();
        assert_eq!(session.session_deadline(), made + vault::SESSION_DAYS * DAY);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_prompt_says_why_the_session_ended() {
        let root = temp("prompt");
        let paths = Paths::new(&root, &root.join("store.multipass"));
        let prompt = |tried| prompt_text(prompt_reason(&paths, tried));
        assert_eq!(prompt(Tried::NoAgent), "Passphrase: ");
        fs::write(&paths.socket, b"").unwrap();
        assert_eq!(prompt(Tried::NoAgent), "Passphrase (the session ended): ");
        for ended in Ended::ALL {
            fs::write(&paths.note, format!("{} 1766000000\n", ended.word())).unwrap();
            assert_eq!(
                prompt(Tried::NoAgent),
                format!("Passphrase ({}): ", ended.reason())
            );
        }
        fs::write(&paths.note, "sleepy 1766000000\n").unwrap();
        fs::remove_file(&paths.socket).unwrap();
        assert_eq!(prompt(Tried::NoAgent), "Passphrase: ");
        fs::remove_dir_all(&root).unwrap();
    }

    /// A running agent leaves a socket and no end note, which is not a
    /// session that ended, so a prompt that did not ask it, or whose request
    /// it could not get a touch for, gives no reason.
    #[test]
    fn a_running_agent_gives_the_prompt_no_reason() {
        let s = setup("running");
        let agent = agent(&s, Fake::always(Approval::Unavailable));
        serving(&agent);
        assert!(s.paths.socket.exists());
        let prompt = |tried| prompt_text(prompt_reason(&s.paths, tried));
        assert_eq!(prompt(Tried::NotAsked), "Passphrase: ");
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Unavailable));
        assert_eq!(prompt(Tried::Unavailable), "Passphrase: ");
        assert_eq!(
            prompt(Tried::Updated),
            "Passphrase (multipass was updated): "
        );
        finish(&agent);
        fs::remove_dir_all(&s.root).unwrap();
    }

    /// A rotation elsewhere ends the session before the agent replies, so
    /// the command that saw `stale` finds the note at once.
    #[test]
    fn the_end_note_is_written_before_the_reply() {
        let s = setup("note-first");
        let agent = agent(&s, Fake::always(Approval::Approved));
        serving(&agent);
        let vault = Vault::new(&s.package, FAST);
        let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
        let mut session = vault.open(&mut ask, now_ms()).unwrap();
        session.rotate(&vault, now_ms(), None).unwrap();
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Stale));
        assert_eq!(
            prompt_text(prompt_reason(&s.paths, Tried::Stale)),
            "Passphrase (the vault key changed): "
        );
        fs::remove_dir_all(&s.root).unwrap();
    }

    /// `serve` returns, and the agent's process exits, only once the
    /// request that ended the session has its reply, so a `lock`, a decline,
    /// or a stale key never leaves the command without an answer. Checked by
    /// reading the reply without blocking once `serve` has returned.
    #[test]
    fn serve_returns_only_after_the_ending_reply_is_out() {
        for (approval, request) in [(Approval::Approved, "lock"), (Approval::Denied, "read")] {
            let s = setup("reply-first");
            let agent = agent(&s, Fake::always(approval));
            let listener = agent.bind().unwrap();
            let serving = {
                let agent = Arc::clone(&agent);
                std::thread::spawn(move || agent.serve(listener))
            };
            let mut stream = UnixStream::connect(&s.paths.socket).unwrap();
            match request {
                "lock" => stream.write_all(b"lock\n").unwrap(),
                _ => write_counted(&mut stream, "read", b"b").unwrap(),
            }
            serving.join().unwrap();
            stream.set_nonblocking(true).unwrap();
            let line = read_line(&mut stream).expect("the reply was written before serve returned");
            assert_eq!(line, if request == "lock" { "ok" } else { "denied" });
            assert!(end_note(&s.paths).is_some());
            assert!(!s.paths.socket.exists());
            fs::remove_dir_all(&s.root).unwrap();
        }
    }

    /// While an older Mac's save to the old single-file store waits to be
    /// merged, the agent answers `unavailable`, so the command prompts and the
    /// prompt merges it, and the agent sends nothing from the package alone.
    #[test]
    fn a_changed_old_file_sends_the_command_to_the_prompt() {
        let root = temp("old-file");
        let old = root.join("store.age");
        let write_old = |secret: &str| {
            let text = format!("multipass 2\nb\n\tsecret {secret}\n");
            fs::write(
                &old,
                crate::age::encrypt(b"pw", text.as_bytes(), FAST).unwrap(),
            )
            .unwrap();
        };
        write_old("one");
        let package = root.join("store.multipass");
        let vault = Vault::new(&package, FAST).with_old(Some(old.clone()));
        let mut ask = |_: vault::Ask| Ok(Some("pw".to_string()));
        let (session, _) = vault.open_or_move(&mut ask, now_ms()).unwrap();
        let agent_dir = root.join("agent");
        store::create_private_dir(&agent_dir).unwrap();
        let s = Setup {
            paths: Paths::new(&agent_dir, &package),
            keys: session.agent_keys(),
            deadline: session.session_deadline(),
            root: root.clone(),
            package,
        };
        let agent = agent(&s, Fake::always(Approval::Approved));
        serving(&agent);
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Entry(_)));
        write_old("two");
        assert!(matches!(client(&s).read("b").unwrap(), Answer::Unavailable));
        assert!(matches!(client(&s).list().unwrap(), Answer::Unavailable));
        finish(&agent);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_agent_switches_follow_the_environment() {
        assert_eq!(enabled(None, None), cfg!(target_os = "macos"));
        assert!(!enabled(Some("1"), None));
        assert!(!enabled(None, Some("10.0.0.1 52000 10.0.0.2 22")));
        assert_eq!(enabled(Some(""), None), cfg!(target_os = "macos"));
    }

    #[test]
    fn the_directory_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp("dir");
        let dir = root.join("agent");
        store::create_private_dir(&dir).unwrap();
        assert!(check_dir(&dir).is_ok());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let refused = check_dir(&dir).unwrap_err();
        assert!(refused.contains(&dir.display().to_string()), "{refused}");
        for peer in [Peer::SameBinary, Peer::SameUser] {
            assert!(matches!(
                connect(&Paths::new(&dir, &root.join("s")), peer),
                Err(Tried::NoAgent)
            ));
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
