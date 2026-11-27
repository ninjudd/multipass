---
status: draft
priority: now
---

# Session unlock

After `multipass unlock`, commands that only read the store run without asking for the passphrase until a background agent locks again, the way `ssh-agent` holds keys for `ssh`.

## 1. Problem

multipass keeps every entry in one age file encrypted under a passphrase. Every command calls `open` in `src/main.rs`, which asks for the passphrase on `/dev/tty` and decrypts the store with `Store::load`. Commands that change the store then re-encrypt it with `Store::save`, which picks a fresh scrypt salt and file key each time, as the age format requires. Nothing outlives the command, so no key stays in memory once it exits.

The cost is a prompt and about 300 ms of scrypt at work factor 18 on every command. Looking up a username, then a password, then a one-time code means typing the passphrase three times. That pushes people toward a short passphrase, the one thing that protects the store, or away from multipass for anything they use often.

## 2. Solution

`multipass unlock` asks for the passphrase once, derives the store's file key, and starts a background agent, `multipass __agent`, that holds only that file key and the header it belongs to. The agent listens on a Unix socket in a 0700 directory, checks that each client runs as the same user, and answers one useful request: it reads the store file from disk, decrypts it with the file key, and returns the store text. `get`, `list`, and `otp` ask the agent first and fall back to the prompt when no agent is unlocked. Commands that save still ask for the passphrase, because the age format forbids reusing a file key or a salt, so every save needs scrypt and the passphrase. After a save, the command hands the new file key to a fresh agent, so the session stays unlocked. The agent locks by exiting: after 10 minutes without a request, 12 hours after unlock, when the Mac sleeps, when the screen locks, and on `multipass lock`.

This design depends on the answers to § 6. Until those are settled, this plan stays a draft.

### 2.1 How a read works

1. You run `multipass unlock`. It asks for the passphrase, reads the store file, and calls `age::unlock`, which runs scrypt, unwraps the file key, and checks the header MAC. A wrong passphrase fails here, and no agent starts.
2. `unlock` starts `multipass --store <path> __agent` as a child, with stdin and stdout piped and stderr discarded. It writes the unlock message (§ 2.4) to the child's stdin and closes it. The file key goes only to a process that `unlock` started itself, never over the socket.
3. The agent calls `setsid`, so closing the terminal does not end it. It denies debugger attachment and core dumps (§ 2.6), checks the file key against the store on disk, binds its socket (§ 2.3), writes `ready` to stdout, and closes stdout. `unlock` waits for `ready`, prints `Unlocked; locks after 10 minutes idle` to stderr, and exits.
4. Later you run `multipass get github.com`. `open` connects to the socket for this store, checks the directory and the peer (§ 2.3), and sends `read`.
5. The agent reads the store file. When the file starts with exactly the header the agent holds, it decrypts the payload with the file key and replies with the store text. When the header differs, because another machine, the passkeys extension, or a prompted save replaced the file, it replies `stale` and exits.
6. `open` parses the text with `Store::from_text`, and the command goes on as today. On `stale`, a refused connection, or no socket, `open` asks for the passphrase as it does today.

### 2.2 How a save works

1. `add`, `rm`, `otp --set`, `otp --clear`, and `passwd` send `status` to the store's agent, then ask for the passphrase and decrypt the store, as today.
2. `Store::save` encrypts with a fresh salt and file key, as today, and now returns the new header and file key that `age::encrypt` produced.
3. When an agent answered `status`, the command sends it `lock`, then starts a fresh agent with the new header and file key, as `unlock` does in § 2.1 steps 2 and 3. The fresh agent keeps the old agent's absolute deadline, which `status` reported, and starts a new idle timer.
4. When no agent answered, the command starts none. Only `unlock` turns session unlock on.

### 2.3 The socket and who may connect

| Part | Value |
| --- | --- |
| Directory | `~/.multipass/agent/`, created with mode 0700 by the existing `create_private_dir`. It stays under `$HOME` even when `MULTIPASS_STORE` points into a synced folder, so the socket never syncs. |
| Socket | `<hash>.sock`, where `<hash>` is the first 16 hex digits of the SHA-256 of the canonical store path. Each store gets its own agent, so `--store` keeps working. The path is public, so hashing it is not cryptography on a secret. |
| Directory check | Before every connect and bind, the client and the agent check that the directory belongs to the current user and has mode 0700, using `std::os::unix::fs::MetadataExt`. Otherwise they refuse to use it and name the directory. |
| Peer check | The agent calls `getpeereid` on each accepted connection and closes any whose user ID differs from its own. The client checks the agent the same way before it sends `read`. |
| Platforms | macOS only in this project, because CI runs only there. On other systems `unlock` fails with `session unlock needs macOS`, and every command prompts as today. |

The agent serves one connection at a time, with a 2-second read timeout, so a client that stalls cannot hold it.

### 2.4 Messages

Every message is one line of ASCII, sometimes followed by a counted run of bytes. No reply names an entry or quotes the store outside the `read` reply, and the agent writes no log.

| Message | Path | Reply |
| --- | --- | --- |
| `unlock <idle-seconds> <deadline-unix> <n>\n`, then `n` bytes: the header through the MAC line, then the 16-byte file key | The agent's stdin, from the process that started it | `ready\n` on stdout, or exit with status 1 |
| `read\n` | Socket | `ok <n>\n` then `n` bytes of store text, or `stale\n` |
| `status\n` | Socket | `unlocked <idle-seconds-left> <deadline-unix>\n` |
| `lock\n` | Socket | `ok\n`, then the agent removes its socket and exits |

The agent never sends the file key, the keys derived from it, or the header MAC. No message carries the passphrase.

### 2.5 When it locks

Locking means the agent removes its socket and exits, so the file key leaves memory with the process. A thread wakes every 5 seconds and locks when any of these holds:

| Trigger | How the agent sees it |
| --- | --- |
| Idle timeout | 10 minutes since the last `read`, by default. `multipass unlock --timeout <minutes>` sets it for that session, from 1 to 720. |
| Absolute deadline | 12 hours after `unlock`, however busy the session is. |
| Sleep | On macOS, `Instant` stops during sleep and `SystemTime` does not. When the wall clock moves more than 30 seconds further than `Instant` between ticks, the machine slept. A change to the clock can trigger it too, which only locks early. |
| Screen lock | The thread runs `/usr/sbin/ioreg -n Root -d1 -a` and reads `IOConsoleLocked`. It locks when the screen goes from unlocked to locked. A session unlocked over SSH while the screen was already locked stays unlocked until the screen has been unlocked and locked again. |
| `multipass lock` | Sends `lock` to the store's agent, and prints `Locked`, or `Not unlocked` when no agent answered. |
| A changed store | The store file no longer starts with the held header (§ 2.1 step 5). |

`ioreg` is a system tool, run the way `src/tty.rs` already runs `/bin/stty`.

### 2.6 What session unlock exposes

An agent trades a prompt per command for a window in which no prompt stands between a process and the store. Inside that window, any process running as you can connect and read every entry, without waiting for you and without anything showing on screen. Without an agent, such a process has to replace the `multipass` binary or a shell alias and wait for your next prompt to capture the passphrase. The locks in § 2.5 keep the window short, but it is still wider than a prompt per command.

| Who | Without an agent | With an unlocked agent |
| --- | --- | --- |
| Another user on the Mac | Cannot read the store | Cannot connect: the directory check and the peer check refuse them |
| Malware running as you, reading | Must trojan the binary and wait for a prompt | Reads every entry at once, until the agent locks |
| Malware running as you, writing | Cannot write a valid store without the passphrase | The same, because saves still need the passphrase |
| Malware running as you, posing as the agent | Nothing to pose as | Can bind the socket while no agent runs and answer `read` with fake store text. It never receives the file key, which crosses only a pipe to a child that `unlock` started. |
| Root, or a debugger | Can read the passphrase from a command's memory while it runs | The agent denies debugger attachment with `ptrace(PT_DENY_ATTACH)`, so a debugger fails, but root can still read the file key. The file key opens this version of the store, not the passphrase or any later version. |
| A crash report or core dump | Could hold the passphrase from a running command | The agent sets `RLIMIT_CORE` to 0, so it leaves no core file |

The README says this plainly beside `unlock`, so you open the window knowingly.

### 2.7 Neighbors: passkeys and the clipboard

- **The passkeys Keychain item.** The passkeys plan's extension keeps the passphrase in a Keychain item that only its own access group can read. The CLI is not signed into that group, so the agent cannot use the item, and the extension cannot use the agent. They stay independent. When the extension saves a new passkey, the store's header changes, the agent replies `stale`, and the next command asks for the passphrase. The passkeys plan's § 2.3 says the CLI "still asks for the passphrase every time"; this project changes that sentence to point here.
- **`--clip`.** `get --clip` and `otp --clip` are a separate feature, in pull request #9. They copy the value through AppKit's `NSPasteboard`, marked current-host-only and concealed. A detached `multipass __clear-clipboard <count>` process clears the clipboard 30 seconds later, and only if the pasteboard's change count still equals `<count>`. `--clip` reads the value through `open`, so it works the same with or without an agent. The clearing process never touches the store, so it does not depend on the agent, which may lock before it runs.

### 2.8 Changes by file

This table assumes pull request #9, which adds `--clip` and `src/clipboard.rs`, merges first.

| File | Change |
| --- | --- |
| `src/age.rs` | `encrypt` also returns an `Unlocked { header: Vec<u8>, file_key: [u8; 16] }`. New `unlock(passphrase, data) -> Result<Unlocked, Error>` does the header half of `decrypt`, and new `decrypt_unlocked(&Unlocked, data)` checks that `data` starts with exactly `header` and decrypts the payload. `decrypt` becomes `unlock` then `decrypt_unlocked`, so the payload code exists once. |
| `src/store.rs` | `Store::save` returns the `Unlocked` from `encrypt`. New `Store::from_bytes(Vec<u8>)` runs the UTF-8 check and `from_text` that `decrypt` runs today, and `decrypt` calls it. |
| `src/agent.rs` | New. The agent half: reads the unlock message from stdin, binds the socket, answers `read`, `status`, and `lock`, and runs the lock thread in § 2.5. The client half: `read`, `status`, `lock`, and `start`, which spawns an agent and writes the unlock message. The socket path and the directory check live here, shared by both halves. The lock decision is a pure function of the deadlines, the two clock readings, and the screen states, so tests can drive it. |
| `src/sys.rs` | New, and the program's second `unsafe` module, built like `src/clipboard.rs`: `unsafe extern "C"` declarations for `getuid`, `getpeereid`, `setsid`, `ptrace(PT_DENY_ATTACH)`, and `setrlimit(RLIMIT_CORE)` behind safe wrappers, under `#[cfg(target_os = "macos")]`, with a comment on each call saying what it requires of its arguments. The standard library offers no stable call for any of them at `rust-version = "1.85"`. |
| `src/clipboard.rs` | Its module comment stops calling it the program's only `unsafe` code, and names `src/sys.rs` as the other module. |
| `src/main.rs` | Adds `unlock [--timeout <minutes>]`, `lock`, and the hidden `__agent` command, named like `__clear-clipboard`. `open` asks the agent for the store before it prompts, and returns no passphrase when the agent answered. Saving commands call a new `open_to_save`, which always prompts, and restart a running agent with the new key after `save`. Updates `USAGE`. |
| `README.md` | Documents `unlock` and `lock`, when the agent locks, and § 2.6's trade in a few sentences. Changes "Every command asks for the passphrase" and removes "Session unlock" from "Not built yet". |
| `AGENTS.md` | Changes the rule "Apple's system frameworks count like the standard library", which says `src/clipboard.rs` "holds the program's only `unsafe` code", so it names `src/clipboard.rs` and `src/sys.rs` as the two modules that hold `unsafe` code, each behind a safe interface. Adds the agent's rules: the file key reaches an agent only through the stdin of a child the CLI started; the agent never sends a key or the passphrase; store text crosses only a socket whose peer passed the user ID check. |
| `docs/projects/passkeys/readme.md` | § 2.3's sentence about the CLI changes as § 2.7 says. |

## 3. Why this design

- **The agent holds the file key, not the passphrase.** The age specification says a file key "MUST NOT be reused across multiple files", and that "A new salt MUST be generated for each stanza and each file". So a key derived from the passphrase can read one version of the store but never write the next one, and an agent that saves must hold the passphrase itself. Holding only the file key keeps the passphrase out of any long-lived process, and it keeps writes behind the prompt, so malware that reaches the agent can read entries but not replace or delete them. Most commands only read, so most prompts go away.
- **The agent reads the file on every request.** It never caches the decrypted store, so plaintext sits in its memory only while it answers, and it notices a store changed by another machine at once rather than serving an old copy. Decrypting a few kilobytes of ChaCha20-Poly1305 takes well under a millisecond.
- **The key crosses a pipe, never the socket.** Any process running as you can bind the socket path while no agent runs. If `unlock` sent the key over the socket, such a process could pose as the agent and collect it. A pipe to a child that `unlock` started itself offers no such opening.
- **Locking means exiting.** One rule covers every trigger, and no locked process stays behind. A later `unlock` starts a fresh process.
- **Sleep is seen through the clocks.** Hearing about sleep from macOS directly needs IOKit's power notifications and a run loop. Comparing `Instant` with `SystemTime` needs only the standard library, and errs toward locking early.
- **Reuse.** The header code in `age::decrypt` moves into `age::unlock` and the payload code into `age::decrypt_unlocked`, and `decrypt` calls the two, so the agent and the prompt decrypt through the same lines. The directory comes from `create_private_dir`, and the socket's hash from `crypto::sha256`.
- **Rejected: an agent that saves.** It would end every prompt, but it keeps the passphrase in memory for the whole session and lets any process running as you rewrite the store. § 6.1 asks whether that trade is wanted.
- **Rejected: holding the passphrase's HMAC state.** The precomputed HMAC-SHA-256 inner and outer states of the passphrase would let the agent run scrypt for any salt without the passphrase's text. But they let an attacker test guesses at SHA-256 speed instead of scrypt speed, which is worse than holding the passphrase.
- **Rejected: a socket path in an environment variable, as `SSH_AUTH_SOCK` does.** A fixed socket path per store lets every terminal find the agent without shell setup. The variable would hold no secret, but it adds setup and gains nothing here.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass unlock`, then `multipass get github.com` | `unlock` asks once. `get` prints the secret without a prompt, in well under 100 ms. |
| `multipass unlock` with a wrong passphrase | Fails with `wrong passphrase, or the store is damaged`, and `~/.multipass/agent/` holds no socket |
| `multipass add x` while unlocked, then `multipass get x` | `add` asks for the passphrase. `get` prints the secret of `x` without a prompt, so the fresh agent holds the new key. |
| Replace the store file with a copy saved elsewhere, then `multipass list` | `list` asks for the passphrase, and the agent has exited |
| `multipass unlock --timeout 1`, wait 70 seconds, then `multipass list` | `list` asks for the passphrase |
| `multipass unlock`, `pmset sleepnow`, wake the Mac, then `multipass list` | `list` asks for the passphrase |
| `multipass unlock`, lock the screen, unlock it, then `multipass list` | `list` asks for the passphrase |
| Over SSH with the screen already locked, `multipass unlock`, wait 30 seconds, then `multipass list` | `list` prints the names without a prompt |
| `multipass lock`, then `multipass lock` again | `Locked`, then `Not unlocked` |
| `chmod 755 ~/.multipass/agent`, then `multipass list` | Refuses to use the agent, names the directory, and asks for the passphrase |
| `lldb -p <agent pid>` | Attaching fails |
| `ps -o args= -p <agent pid>` | Shows `multipass --store <path> __agent` and nothing secret |

Tests that must fail before the change and pass after it:

- **`age::unlock` then `decrypt_unlocked`** decrypts each `testdata/reference-*.age` fixture, so the split cannot change what `decrypt` accepts. Catches an off-by-one in where the header ends.
- **`decrypt_unlocked` rejects a file whose header differs by one byte** from the held one, and a file encrypted again under the same passphrase. Catches an agent that serves a stale key against a new file.
- **The `Unlocked` that `encrypt` returns decrypts the file `encrypt` wrote.** Catches a save that hands the fresh agent the old key.
- **The unlock message** round-trips through its writer and reader, and the reader rejects a short key, a missing count, and trailing bytes. Catches a key that arrives truncated.
- **The lock decision**, table-driven over the idle deadline, the absolute deadline, the two clock readings, and the previous and current screen states. It covers each trigger, the 30-second sleep threshold on both sides, and the SSH case where the screen starts locked. Catches a session that never locks after sleep and one that locks at once over SSH.
- **The directory check** refuses a directory with mode 0755 and accepts 0700, in a temporary directory. Catches a socket other users could reach.
- **An agent end to end**, in a temporary directory at work factor 10: start it with a store's `Unlocked`, and `read` returns the store text, `status` reports the idle time left, rewriting the store makes `read` return `stale`, and `lock` removes the socket. Catches a message format the two halves disagree on.

## 5. Cost

Unlocked reads drop from about 300 ms of scrypt to one socket round trip, one file read, and a ChaCha20-Poly1305 decryption of a few kilobytes, a few milliseconds in all. `unlock` and every save still run scrypt once, and a save while unlocked also starts a process, a few milliseconds more. The lock thread spawns `ioreg` every 5 seconds. The implementer measures the agent's CPU time over an hour with `ps -o time=` and records it in § 7, and moves the poll to 10 seconds if it exceeds 1% of a core. Between requests the agent holds a header and a 16-byte key.

## 6. Open questions

Questions 6.1 to 6.4 wait on the user. § 2 is written for each recommended answer.

### 6.1 What the agent holds

Recommended: the file key and header only, so reads skip the prompt and saves still ask, as § 2 and § 3 describe. The alternative is the passphrase. Then nothing prompts until the agent locks, the agent runs scrypt and writes the store on each save, the passphrase stays in its memory for the session, where root can read it, and any process running as you can rewrite or empty the store. Owner: the user.

### 6.2 When it locks

Recommended: 10 minutes idle, 12 hours at most, `--timeout` from 1 to 720 minutes, and locking on sleep, on screen lock, and on `multipass lock`, as § 2.5 describes. Owner: the user.

### 6.3 Who may connect

Recommended: any process running as you, enforced by the 0700 directory and checked with `getpeereid`, with `src/sys.rs` as a second `unsafe` module beside `src/clipboard.rs`, following the rule that pull request #9 adds to `AGENTS.md`. The same module denies debuggers and core dumps. One alternative is the directory check alone, which needs no `unsafe` but leaves the agent open to a debugger and to a core dump. The other binds the agent to the terminal session that unlocked it, as `sudo` binds its timestamp to a terminal, which needs more system calls and breaks scripts and editors that run multipass outside that terminal. Owner: the user.

### 6.4 How it starts

Recommended: only `multipass unlock` starts an agent. Other commands use an agent when one runs and prompt otherwise, so nothing changes for someone who never runs `unlock`. The alternatives are starting an agent from every command that prompts, which opens the window for everyone; `eval $(multipass agent)` in each shell, as `ssh-agent` does, which needs shell setup and gives each terminal its own agent; and a launchd agent started at login, which needs an install step and still needs `unlock` to receive the key. Owner: the user.

## 7. Background

- `ssh-agent` holds private keys and signs for its clients, so a key never leaves it. It also checks each client with `getpeereid` and, on macOS, denies debugger attachment with `PT_DENY_ATTACH`. multipass cannot copy the signing model, because decrypting the store means handing the client its text, but it copies the socket checks and the hardening.
- The age specification (C2SP's `age.md`) requires a fresh file key per file, a fresh payload nonce per file, and a fresh scrypt salt per stanza and file. That rules out an agent that saves with a cached key.
- `ioreg -n Root -d1 -a` prints `IOConsoleLocked` as `<false/>` on an unlocked Mac. The implementer confirms that it reads `<true/>` with the screen locked before relying on it, and records the result here.
- On macOS, `std::time::Instant` reads a clock that stops during sleep, while `SystemTime` reads the wall clock. The sleep check in § 2.5 depends on that difference, and the `pmset sleepnow` row of § 4 checks it.
