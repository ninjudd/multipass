---
status: draft
priority: now
---

# Session unlock

After you type the passphrase once, a background agent keeps the store unlocked until its vault key expires, at most 21 days, and every later read or change asks for a touch of Touch ID or a press on an Apple Watch, naming the entry it is for, instead of the passphrase.

This project depends on the [vault key](../vault-key/readme.md), which in turn depends on the [mergeable store](../store-merge/readme.md); both ship first. With them, the passphrase unlocks a random vault key, the vault key encrypts the store's files, every save adds a new file that is never modified, and opening merges the files entry by entry. So the agent can read and save holding only the vault key, and saves on two Macs never overwrite each other.

## 1. Problem

Every multipass command asks for the passphrase on `/dev/tty` and runs scrypt at work factor 18, about 300 ms, on the store today and on the key file once the vault key ships. Nothing outlives the command, so no key stays in memory once it exits. Looking up a username, then a password, then a one-time code means typing the passphrase three times. That pushes people toward a short passphrase, the one thing that protects the store, or away from multipass for anything they use often.

The prompt also guarantees something a fix must keep: only a person who knows the passphrase can read or change the store. A program running as you cannot, and that includes an AI coding agent that runs shell commands for you. Even one that fakes a terminal with `expect` still lacks the passphrase.

## 2. Solution

Whenever a command has to ask for the passphrase, it gets the vault key from the package's key file, as the vault-key plan describes, and starts a background agent, `multipass __agent`, holding only that key. The agent listens on a Unix socket in a 0700 directory, checks that each client runs as the same user from the same `multipass` binary, and answers requests for one entry at a time: read it, change it, or list the names. Each request asks you to approve with Touch ID or an Apple Watch, on a sheet that names the entry, such as "multipass is trying to read github.com". Only after you approve does the agent decrypt the store and answer, or save the change. So no program can read or change an entry without your finger on the sensor, a request you did not make shows up as a sheet for an entry you did not ask about, and declining it ends the session. After the first prompt, `get`, `list`, `add`, `rm`, and `otp` each cost one touch, and only `init`, `passwd`, and `rekey` still ask for the passphrase.

A session ends when the vault key expires, 21 days after the key was made, whatever time the session started. Any passphrase prompt rotates a key that is 14 or more days old, as the vault-key plan's § 2.5 describes, so a session always starts with at least 7 days left, and without restarts you type the passphrase about every 21 days. A session also ends on a restart, on `multipass lock`, when you decline a request, and when another Mac rotates the key. Sleep, the screen lock, and time without use do not end it. The next command then asks for the passphrase, says why, and starts a fresh session. `multipass status` tells you whether the store is unlocked and until when. Over SSH, and wherever Touch ID and a watch are both unavailable, no agent starts, and every command prompts as today.

The agent keeps the vault key in protected memory: it denies debugger attachment, writes no core file, locks the key's page out of swap, and wipes it on exit. Root or a kernel exploit can still copy it during a session (§ 2.7). § 8 designs a Secure Enclave mode for the signed Mac app from the passkeys plan, in which the agent holds only a copy of the key wrapped by the enclave, and the enclave itself demands the touch. That mode ships with the app, not in this project.

Starting a session without being asked, and keeping it for two weeks, is safe only because every request needs your touch (§ 2.8). Without that touch, such a session would let any program running as you read and rewrite the store silently.

This plan stays a draft until the prototype in § 6.5 confirms that the agent can show the Touch ID sheet.

### 2.1 How a session starts

1. You run any command, such as `multipass get github.com`, and no agent answers for this store, or `open` skips the agent (§ 2.4). The command asks for the passphrase on `/dev/tty`, as today. When an earlier session for this store has ended, the prompt says why, such as `Passphrase (the session ended): ` (§ 2.4).
2. `open` opens the package with the vault-key plan's `vault::open`, which merges its store files and rotates the key when it is 14 or more days old, and the command runs. A wrong passphrase fails here, and no agent starts.
3. When the command succeeds, and neither `MULTIPASS_NO_AGENT` nor `SSH_CONNECTION` is set, it starts `multipass --store <path> __agent` as a child, with stdin and stdout piped and stderr discarded. It writes the start message (§ 2.6) to the child's stdin and closes it. The vault key goes only to a process the command started itself, never over the socket.
4. The agent calls `setsid`, so closing the terminal does not end it. It protects its memory (§ 2.7) and asks LocalAuthentication whether Touch ID or an Apple Watch can approve requests (§ 2.8). When neither can, it exits, and no session starts. Otherwise it checks the vault key against the store, binds its socket (§ 2.5), removes the store's end note (§ 2.4), writes `ready` to stdout, and closes stdout.
5. The command waits up to 2 seconds for `ready` and then exits. It says nothing about the agent either way, so a failed start costs nothing but the next prompt.

### 2.2 How a read works while unlocked

1. You run `multipass get github.com`. `open` connects to the socket for this store, checks the directory and the peer (§ 2.5), and sends `read github.com`. `list` sends `list` instead.
2. The agent asks for approval (§ 2.8), and macOS shows its Touch ID sheet: "multipass is trying to read github.com", or "multipass is trying to list your entries". When you cancel, or leave the sheet for 60 seconds, it replies `denied` and exits. When Touch ID and the watch are both unavailable at that moment, such as with the lid closed and no watch in reach, it replies `unavailable` and stays unlocked.
3. When you approve, the agent lists the package. When it holds a key file of another generation, or a store file under a generation the agent has no key for, a rotation ran on another Mac, so it replies `stale` and exits. Otherwise it decrypts every store file and merges them with `Store::merge`, and compacts them into one new file when there were several, as the vault-key plan's § 2.3 describes. It then replies with that one entry, as store text holding only it, or `missing` when there is none. `list` gets the names and nothing else.
4. `open` parses the reply with `Store::from_text`, and the command goes on as today. On `denied`, the command fails with `the request was not approved`, and the next command asks for the passphrase. On `stale` or `unavailable`, or when no agent answers, `open` asks for the passphrase and a session starts as § 2.1 describes.

A store saved on another machine still opens, because both machines share the vault key through the synced key file.

### 2.3 How a change works while unlocked

1. You run `multipass add x`. `open_to_save` connects and sends `edit x`.
2. The agent asks for approval with the reason `change x`. On approval it merges the store files as § 2.2 step 3 describes, and replies with entry `x` as store text, or `missing`. The connection stays open while the command asks for the secret, for up to 5 minutes.
3. The command makes its change and sends `save` with store text holding the new `x`, or holding nothing to remove `x`.
4. The agent refuses with `refused` when the text holds any entry other than `x`. Otherwise it merges the store files again, since another Mac or command may have saved meanwhile, puts `x` or a tombstone for it with a fresh stamp, writes the result as a new store file, deletes the files it read, and replies `saved`. A save that another command makes at the same moment writes its own new file, and the next request merges both.
5. When no agent answers, the command asks for the passphrase, opens the store, saves with the vault key, and starts a session as § 2.1 describes.

`init`, `passwd`, and `rekey` always ask for the passphrase, because they write the key file, which the passphrase encrypts. `passwd` and `rekey` both rotate the vault key, so they send `lock` to the old agent and start a fresh one with the new key. Agents on other Macs find on their next request that the key no longer opens the store, and end with `the vault key changed`. That is rare, and costs each Mac one prompt.

### 2.4 Commands, prompts, and settings

| Name | What it does |
| --- | --- |
| `multipass status` | Prints `unlocked until Dec 10 14:32`, or `locked`, followed by the reason from the end note when there is one, such as `locked: you declined a request at 13:05`. It asks for nothing. |
| `multipass lock` | Sends `lock` to the store's agent, and prints `Locked`, or `Not unlocked` when no agent answered. |
| The end note | When an agent ends, it writes `<hash>.ended` beside its socket, holding the reason and the time, such as `declined 1764160000`. The note holds no secret. The prompt and `status` read it, and a starting agent removes it. |
| The prompt | `Passphrase: ` when there is no end note and no socket, and otherwise `Passphrase (<reason>): `: `the vault key expired`, `you declined a request`, `the vault key changed`, `locked by multipass lock`, or `the session ended` when a socket is left with no agent behind it and no note, as after a restart. |
| `MULTIPASS_NO_AGENT=1` | `open` never asks an agent and no command starts one, so every command prompts as today. |
| `SSH_CONNECTION` | When it is set, `open` skips the agent and no command starts one. Nobody at the far end of SSH can touch the Mac's sensor, so asking would only leave a sheet on the Mac's screen until it times out and ends the session. |

Neither environment variable carries a secret, so the rule against secrets in the environment does not apply to them.

### 2.5 The socket and who may connect

| Part | Value |
| --- | --- |
| Directory | `~/.multipass/agent/`, created with mode 0700 by the existing `create_private_dir`. It stays under `$HOME` even when `MULTIPASS_STORE` points into a synced folder, so the socket never syncs. |
| Socket | `<hash>.sock`, where `<hash>` is the first 16 hex digits of the SHA-256 of the canonical package path. Each store gets its own agent, so `--store` keeps working. The path is public, so hashing it is not cryptography on a secret. |
| Directory check | Before every connect and bind, the client and the agent check that the directory belongs to the current user and has mode 0700, using `std::os::unix::fs::MetadataExt`. Otherwise they refuse to use it and name the directory. |
| Peer check | The agent calls `getpeereid` on each accepted connection and closes any whose user ID differs from its own. The client checks the agent's user ID the same way, and also that the agent runs the same executable as the client, from `LOCAL_PEERPID` and `proc_pidpath`, before it sends anything. This is the first gate, and the touch in § 2.8 is the second. |
| Platforms | macOS only, because Touch ID approval is macOS's and CI runs only there. On other systems no agent starts, and every command prompts as today. |

The agent handles each connection on its own thread, so an open `edit` does not hold up a `get`. It shows one Touch ID sheet at a time, and gives a client 2 seconds to send each request, so a client that stalls cannot hold it.

### 2.6 Messages

Every request is one line of ASCII, followed by a counted run of bytes where it carries a name or store text. No reply quotes the store beyond what the request asked for, and the agent writes no log.

| Message | Path | Reply |
| --- | --- | --- |
| `start <deadline-unix> <n>\n`, then the `n` bytes of the key file's text: the current vault key, its creation time, and the retired keys. The deadline is the key's creation time plus 21 days. | The agent's stdin, from the process that started it | `ready\n` on stdout, or exit with status 1 |
| `read <n>\n`, then an entry name | Socket | `ok <n>\n` then store text holding only that entry, or `missing\n`, `denied\n`, `unavailable\n`, or `stale\n` |
| `list\n` | Socket | `ok <n>\n` then the entry names, one per line, escaped as the store escapes them, or `denied\n`, `unavailable\n`, or `stale\n` |
| `edit <n>\n`, then an entry name | Socket | The same as `read`, and on `ok` or `missing` the connection waits for `save` |
| `save <n>\n`, then store text holding the named entry or nothing | Socket, after `edit` on the same connection | `saved\n` or `refused\n` |
| `status\n` | Socket | `unlocked <deadline-unix>\n` |
| `lock\n` | Socket | `ok\n`, then the agent writes its end note, removes its socket, and exits |

The agent never sends the vault key, and no message carries the passphrase. `status` and `lock` need no approval: the first reveals only that an agent runs, and the second can only end it.

### 2.7 What session unlock exposes

An agent trades a passphrase per command for a touch per request, and holds the vault key, and the retired keys from the key file, in memory between them, for up to 21 days. The touch keeps what the prompt guaranteed: no program can read or change an entry without a person at the Mac. What it loses is the knowledge factor. A person at your Mac, once past its own lock screen, can use the store with an enrolled finger or your watch, without knowing the passphrase, until the session ends. Because sessions start on their own, everyone who uses multipass on a Mac with Touch ID or a watch has such a session after each prompt, unless they set `MULTIPASS_NO_AGENT=1`.

The agent protects the vault key in memory in four ways, all in `src/sys.rs`. `ptrace(PT_DENY_ATTACH)` refuses debuggers. `setrlimit(RLIMIT_CORE, 0)` means a crash leaves no core file. `mlock` keeps the key's page out of swap. And the agent overwrites the key with zeros before it exits. It also zeroes the decrypted store buffer it owns after each reply. Strings made while parsing are not wiped; the README's planned memory-wiping work covers those.

| Who | Without an agent | With an unlocked agent |
| --- | --- | --- |
| Another user on the Mac | Cannot read the store | Cannot connect: the directory check and the peer check refuse them |
| An AI coding agent running commands as you | Cannot answer the `/dev/tty` prompt without the passphrase, even through a fake terminal | Each `multipass get` or `add` it runs puts a Touch ID sheet on your screen, naming the entry. Nothing it can do presses the sensor or the watch, and declining ends the session. It cannot start a session either, because starting one takes the passphrase. |
| Malware running as you, reading | Must trojan the binary and wait for a prompt | The same as an AI agent, with one opening: it can send its request just before one of your own commands, so your touch approves its request. It then learns one entry, and the sheet named that entry, not the one you asked for. Your own command then asks a second time, which is a second sign. Declining ends the session. |
| Malware running as you, writing | Cannot write a valid store without the passphrase | Needs a touch, with the same opening, and a stolen touch can silently change or delete one entry. The agent saves only the entry the sheet named, so the damage stops at that entry, and a sheet saying `change github.com` when you ran `get bank` is the sign. A backup brings the entry back. |
| Malware running as you, posing as the agent | Nothing to pose as | Must run the `multipass` binary to pass the client's executable check, and that binary only ever holds a key a command handed it. A program that can replace the binary can already capture the passphrase at the next prompt, without an agent. |
| A person at your Mac, past its lock screen | Needs the passphrase | Needs an enrolled finger or your watch, for up to 21 days |
| Root, or a kernel exploit | Can read the passphrase from a command's memory while it runs | Can copy the vault key from the agent's memory at any time in the session, without a touch. The LocalAuthentication check runs inside the agent, so root can also skip it. The vault key opens every copy of the store written under it, here, in sync, and in backups, until the next rotation, at most 21 days later, or `multipass rekey` now. It does not reveal the passphrase. § 8's enclave mode narrows this. |
| A crash report or core dump | Could hold the passphrase from a running command | The agent leaves no core file |

The README says this plainly, names `MULTIPASS_NO_AGENT=1` for anyone who wants a prompt every time, shows `multipass lock` for ending a session early, and says to run `multipass rekey` if the Mac may have been compromised.

### 2.8 Approval with Touch ID or an Apple Watch

| Part | Value |
| --- | --- |
| Framework | LocalAuthentication's `LAContext`, called from `src/touch_id.rs` through the Objective-C runtime, as `src/clipboard.rs` calls AppKit. It needs no Keychain item and no entitlement, so it works from an unsigned command-line program. |
| Policy | `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch`: a finger on Touch ID, or a double press on a paired Apple Watch. Not `LAPolicyDeviceOwnerAuthentication`, which falls back to the login password, because a program that knows or captures that password could type it. |
| At start | `canEvaluatePolicy` must succeed, or the agent exits and no session starts (§ 2.1 step 4). |
| Each request | A fresh `LAContext` and one `evaluatePolicy` call. The reason is `read <name>`, `change <name>`, or `list your entries`, with the name escaped as the store escapes it and cut to 60 characters. One approval covers one request, with no grace period. |
| Approved | The agent goes on with the request. |
| Cancelled, failed, or 60 seconds with no answer | The agent replies `denied`, calls `invalidate` on the context, writes its end note, and exits. A request you did not expect means something else asked, so the agent stops serving anyone. |
| Unavailable at that moment | `LAErrorBiometryNotAvailable`, `LAErrorBiometryLockout`, or no watch in reach: the agent replies `unavailable` and stays unlocked, and the command asks for the passphrase. |

The reply arrives in an Objective-C block on a queue LocalAuthentication owns. `src/objc.rs` builds that block by hand, a global block with no captured variables, and the block hands the result to the waiting agent thread through a `std::sync::mpsc` channel.

### 2.9 When a session ends

Ending means the agent writes its end note, wipes the vault key, removes its socket, and exits. It costs you one passphrase prompt on the next command, which starts a fresh session.

| Trigger | How it happens |
| --- | --- |
| The vault key expires | A thread sleeps until the key's creation time plus 21 days, by the wall clock, so time asleep counts. Every Mac's agent for that key ends at the same moment. A session starts with at least 7 days left, because the prompt that starts it rotates a key 14 or more days old, and the prompt after expiry rotates too. |
| A restart or logout | The agent is a process, so it ends with the login session and writes no note. Its socket file stays behind, which is how the next prompt knows to say `the session ended`. |
| A declined request | § 2.8. |
| `multipass lock` | § 2.4. |
| A rotation elsewhere | The package holds a key file of another generation (§ 2.2 step 3), after a rotation on another Mac, by early rotation, expiry, `passwd`, or `rekey`. A Mac that prompted on the key's thirteenth day, and so did not rotate, loses its session when another Mac rotates on day 14 or later, possibly a day or two after its own prompt. That happens at most once per rotation, and the vault-key plan's § 2.5.1 says why it cannot be avoided: age requires an scrypt stanza to be a file's only stanza, so no file can be under both the old key and the new. |

### 2.10 Neighbors: passkeys and the clipboard

- **The passkeys app.** The passkeys plan's extension keeps the passphrase in a Keychain item that only its own access group can read. The CLI is not signed into that group, so this project's agent cannot use the item. Once the vault key ships, the extension could keep the vault key there instead of the passphrase; the passkeys plan decides that. The app is also where § 8's enclave mode lands. The passkeys plan's § 2.3 says the CLI "still asks for the passphrase every time"; this project changes that sentence to point here.
- **`--clip`.** `get --clip` and `otp --clip` are a separate feature, in pull request #9. They copy the value through AppKit's `NSPasteboard`, marked current-host-only and concealed. A detached `multipass __clear-clipboard <count>` process clears the clipboard 30 seconds later, and only if the pasteboard's change count still equals `<count>`. `--clip` reads the value through `open`, so it asks for the same touch as `get`. The clearing process never touches the store, so it does not depend on the agent.

### 2.11 Changes by file

This table assumes the mergeable-store and vault-key plans have shipped, and that pull request #9, which adds `--clip` and `src/clipboard.rs`, merged first.

| File | Change |
| --- | --- |
| `src/store.rs` | No new code. The agent builds its one-entry replies with `Store::new`, `insert`, and `to_text`. |
| `src/vault.rs` | No new code. The agent lists, merges, compacts, and saves the package through the functions the vault-key plan adds, given the keys it holds. |
| `src/agent.rs` | New. The agent half: reads the start message from stdin, binds the socket, answers `read`, `list`, `edit` and `save`, `status`, and `lock` on a thread per connection, enforces the one-entry rule on `save`, ends the session as § 2.9 says, and writes the end note. It asks for approval through an `Approver` trait, which `touch_id::TouchId` implements and tests replace with a fake. The client half: `read`, `list`, `edit`, `status`, `lock`, `end_note`, and `start`, which spawns an agent and writes the start message. The socket path, the end note's path, and the directory check live here, shared by both halves. |
| `src/touch_id.rs` | New `unsafe` module. Links `LocalAuthentication.framework`, and wraps `canEvaluatePolicy:error:`, `evaluatePolicy:localizedReason:reply:`, and `invalidate` in a safe `TouchId::available()` and `TouchId::approve(reason, timeout) -> Approval`, where `Approval` is `Approved`, `Denied`, or `Unavailable`. |
| `src/objc.rs` | New `unsafe` module. The typed `objc_msgSend`, class, selector, and `NSString` helpers move here from `src/clipboard.rs`, so the clipboard and Touch ID share one copy, and it adds the global block that carries `evaluatePolicy`'s reply. |
| `src/clipboard.rs` | Calls the helpers in `src/objc.rs` instead of defining its own. Its module comment stops calling it the program's only `unsafe` code. |
| `src/sys.rs` | New `unsafe` module, built like `src/clipboard.rs`: `unsafe extern "C"` declarations for `getuid`, `getpeereid`, `getsockopt(LOCAL_PEERPID)`, `proc_pidpath`, `setsid`, `ptrace(PT_DENY_ATTACH)`, `setrlimit(RLIMIT_CORE)`, and `mlock`, behind safe wrappers, plus `wipe(&mut [u8])`, which zeroes with volatile writes. All under `#[cfg(target_os = "macos")]`. The standard library offers no stable call for any of them at `rust-version = "1.85"`. |
| `src/main.rs` | Adds `status`, `lock`, and the hidden `__agent` command, named like `__clear-clipboard`. `get` and `otp` ask the agent with `read`, and `list` with `list`, unless § 2.4's variables say not to. `add`, `rm`, `otp --set`, and `otp --clear` call a new `open_to_save`, which asks with `edit` and saves with `save`. Both fail on `denied`, and otherwise prompt with the reason from the end note and start an agent once the command succeeds. `init`, `passwd`, and `rekey` always prompt, and `passwd` and `rekey` replace the agent. Updates `USAGE`. |
| `README.md` | Documents sessions: the touch for each request, when a session ends, `status`, `lock`, `MULTIPASS_NO_AGENT`, and § 2.7's trade in a few sentences, with `rekey` as the remedy for a suspected compromise. Changes "Every command asks for the passphrase" and removes "Session unlock" from "Not built yet". |
| `AGENTS.md` | Changes the rule "Apple's system frameworks count like the standard library", which says `src/clipboard.rs` "holds the program's only `unsafe` code", so it names `src/objc.rs`, `src/clipboard.rs`, `src/touch_id.rs`, and `src/sys.rs` as the modules that hold `unsafe` code, each behind a safe interface, with a comment on each call saying what it requires of its arguments. Adds the agent's rules: the vault key reaches an agent only through the stdin of a child the CLI started; the agent answers a request only after an approval for that one request, and only for the entry it names; it never sends the vault key. |
| `docs/projects/passkeys/readme.md` | § 2.3's sentence about the CLI changes as § 2.10 says. |

## 3. Why this design

- **The agent holds the vault key.** The age specification says a file key "MUST NOT be reused across multiple files", and that "A new salt MUST be generated for each stanza and each file", so every save needs scrypt and whatever secret the store is encrypted under. With the vault-key plan, that secret is a random key that never leaves multipass, so the agent can save without holding the passphrase, and the passphrase sits in memory only during a prompt.
- **A touch for every request.** The worry this design answers is a program, an AI coding agent above all, that runs `multipass` as you while the store is unlocked. Every way to tell such a program from you in software fails, because it runs as you, can start from your terminal, and can fake a terminal or click a dialog. A finger on Touch ID or a press on the watch is physical, so it is the one check no program can pass. Asking on every request, with no grace period, means a program can never ride on an approval you gave a moment earlier.
- **One entry per request, named on the sheet.** If a program does steal a touch by timing its request just before yours, the sheet shows the entry it asked for, and the agent hands over or changes only that entry. A stolen touch then costs one entry rather than the store, and the wrong name on the sheet is easy to notice. This matters most for changes, where a stolen touch could otherwise delete or replace every entry silently.
- **Sessions start on their own and end when the vault key expires.** The key's creation time sits in the synced key file, so every Mac agrees on the deadline without talking to the others, and the rotation that ends the session also retires the key an attacker might have copied. An explicit `unlock` command would make you keep track of whether the last session has ended, and people are bad at keeping track of time. A command that already had to prompt starts a session at no extra cost, and the prompt's reason tells you why it asked again. The case for short sessions, and for an explicit `unlock`, was that an unlocked store lets programs read it. The touch for every request takes that away, so what a long session still costs is the vault key's time in memory, where only root or a kernel exploit can reach it. 1Password's Touch ID unlock makes a similar trade: it asks for the account password after a restart, and otherwise on a schedule you set.
- **No locking on sleep, the screen lock, or idle time.** Each would add passphrase prompts without stopping anything the touch does not already stop. A person at the Mac must first get past its own lock screen.
- **Declining ends the session.** A sheet you did not expect is evidence that something else is asking. Ending the session stops a program from asking again and again until a reflexive touch approves it, and the cost is typing the passphrase once after a mistaken cancel.
- **Unavailable falls back to the passphrase.** With the lid closed and no watch, the passphrase prompt still proves a person is there, so it is a safe fallback. A cancelled sheet does not fall back, because that would let a program turn your "no" into a second chance.
- **SSH skips the agent.** `SSH_CONNECTION` comes from the SSH server and a client could ignore it, so the check is a courtesy, not a gate: a client that ignores it gets a sheet on the Mac like any other. It keeps a remote command from leaving a sheet nobody can answer, which would time out and end the session at the desk.
- **Protected memory now, the enclave with the app.** Every protection in § 2.7 works from an unsigned command-line program. The Secure Enclave would keep the plaintext key out of memory between requests, but it likely needs a signed app with entitlements, which the passkeys plan builds. So this project ships the mode that works today, and § 8 designs the enclave mode for the app.
- **The agent reads the file on every request.** It never caches the decrypted store, so plaintext sits in its memory only while it answers, and a store saved on another machine is served as it now is.
- **The key crosses a pipe, never the socket.** Any process running as you can bind the socket path while no agent runs. If a command sent the key over the socket, such a process could pose as the agent and collect it. A pipe to a child the command started itself offers no such opening.
- **Ending means exiting.** One rule covers every trigger, and no locked process stays behind. The end note outlives the process only to explain the next prompt.
- **Reuse.** The agent decrypts through `Store::decrypt` and saves through `Store::save`, so it reads and writes the store exactly as a prompted command does, and its one-entry replies are ordinary store text that `Store::from_text` already parses. The Objective-C helpers move out of `src/clipboard.rs` into `src/objc.rs`, so Touch ID does not repeat them. The directory comes from `create_private_dir`, and the socket's hash from `crypto::sha256`.
- **Rejected: returning the whole store on each request.** It is simpler, but one stolen touch would hand over every entry, and one stolen change could rewrite them all.
- **Rejected: `eval $(multipass agent)` in each shell, as `ssh-agent` does.** It needs a line in your shell setup, and gives each terminal its own agent, so a second window asks again.
- **Rejected: a launchd agent started at login.** It needs an install step, and it would still need the passphrase from some command before it could read anything, so it saves nothing over starting on demand.
- **Rejected: binding the agent to the terminal that started it.** Anything started from that terminal inherits it, an AI agent included, and a program can open a terminal of its own.
- **Rejected: a click-to-allow dialog.** A program with accessibility or screen-control access can click it, and people learn to click it without reading.
- **Rejected: any process running as you, with no approval.** It reads silently, so an AI agent running as you could read every entry while the store is unlocked.
- **Rejected: a socket path in an environment variable, as `SSH_AUTH_SOCK` does.** A fixed socket path per store lets every terminal find the agent without shell setup.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| With no agent running, `multipass get github.com` | Asks `Passphrase: `, prints the secret, and an agent is running afterwards |
| `multipass get github.com` again, and touch the sensor | No passphrase prompt. The sheet says "multipass is trying to read github.com", then the secret prints. |
| `multipass get github.com` a third time, right away | The sheet appears again: one touch covers one request |
| `multipass list`, and touch the sensor | The sheet says "list your entries", and the names print |
| `multipass add x`, touch the sensor, and type the secret | One sheet, saying "change x", and no passphrase prompt. `multipass get x` and a touch then print the secret. |
| `multipass get github.com`, and cancel the sheet | `get` fails with `the request was not approved`, and the agent has exited. The next `get` asks `Passphrase (you declined a request): `. |
| `multipass get github.com`, and leave the sheet for 60 seconds | The same as cancelling |
| While unlocked, run `multipass get github.com` from a script started with no terminal | The Touch ID sheet appears, and nothing prints until someone touches the sensor |
| Over SSH, `multipass get github.com` while an agent runs at the desk | Asks for the passphrase, shows no sheet on the Mac, and the desk's agent keeps running |
| `MULTIPASS_NO_AGENT=1 multipass get github.com` twice | Both ask for the passphrase, and no agent starts |
| With the lid closed, an external display, and no Apple Watch, `multipass get github.com` while unlocked | `get` asks for the passphrase, and the agent stays unlocked |
| `pmset sleepnow` while unlocked, wake the Mac, then `multipass get github.com` | Only the sheet, no passphrase prompt |
| Restart the Mac, then `multipass list` | Asks `Passphrase (the session ended): ` |
| `multipass add x` and `multipass add y` at once, each touched | Both save. `multipass list` and a touch show both, and the package holds one store file again. |
| `multipass rekey` while unlocked, then `multipass get github.com` | `rekey` asks for the passphrase. `get` asks only for a touch, so the fresh agent holds the new key. |
| `multipass passwd` or `multipass rekey` on another machine, let both files sync, then `multipass get github.com` here and touch the sensor | Asks `Passphrase (the vault key changed): ` |
| `multipass status` while unlocked, then `multipass lock`, `multipass lock`, `multipass status` | `unlocked until …` at the vault key's expiry, at least 7 and at most 21 days out, then `Locked`, then `Not unlocked`, then `locked: locked by multipass lock …` |
| `chmod 755 ~/.multipass/agent`, then `multipass list` | Refuses to use the agent, names the directory, and asks for the passphrase |
| `lldb -p <agent pid>` | Attaching fails |
| `ps -o args= -p <agent pid>` | Shows `multipass --store <path> __agent` and nothing secret |

Tests that must fail before the change and pass after it:

- **The start message** round-trips through its writer and reader, and the reader rejects a short key, a missing count, and trailing bytes. Catches a key that arrives truncated.
- **The approval gate**, with a fake `Approver` that counts its calls and records each reason. Two `read`s call it twice, `read github.com` asks with `read github.com`, and `edit x` asks with `change x`. `Denied` sends `denied`, sends no store bytes, writes the end note, and the agent exits. `Unavailable` sends `unavailable` and the agent keeps serving. Catches an agent that sends text before approval, a grace period that slips in, a sheet that names the wrong entry, and a cancel that does not end the session.
- **One entry per request.** With an approving fake and a store of three entries, `read b` returns only `b`, `list` returns the three names and no fields, and a `save` after `edit b` that also holds `c`, or holds `c` instead of `b`, gets `refused` and leaves the file unchanged. Catches an agent that hands over the whole store, and a stolen change that rewrites other entries.
- **`edit` and `save`.** `save` with a new `b`, and with no entries, puts `b` and leaves a tombstone for it, and `vault::open` with the passphrase then reads the result. A store file that another process writes between `edit` and `save` survives the save, and the next `read` merges it. A `save` with no `edit` before it on the connection is refused. Catches a save that deletes a file it did not read, and a save that skips approval.
- **Another generation.** A key file of a new generation copied into the package makes the next `read` reply `stale` and end the session with `the vault key changed`. Catches an agent that keeps saving under a retired key.
- **The deadline**: the deadline a command passes to a new agent is the vault key's creation time plus 21 days, not the session's start, and an agent given a deadline in the past ends at once with `the vault key expired`. Catches a session that outlives its key, and one that a busy week keeps alive forever.
- **The end note and the prompt.** Each reason the agent writes turns into its prompt text. A socket with no agent behind it gives `the session ended`, and a missing note, or one with an unknown reason, gives `Passphrase: `. Catches a prompt that blames the wrong cause.
- **The agent switches in `open`**, as a pure function of `MULTIPASS_NO_AGENT` and `SSH_CONNECTION`. Catches an opt-out that still starts an agent.
- **`sys::wipe`** leaves a buffer all zeros. Catches a wipe the compiler optimizes away, which is why it uses volatile writes.
- **The directory check** refuses a directory with mode 0755 and accepts 0700, in a temporary directory. Catches a socket other users could reach.
- **An agent end to end**, in a temporary directory with an approving fake: start it with a vault key, and `read` returns an entry, `status` reports the deadline, a store re-encrypted under another key makes `read` return `stale`, and `lock` removes the socket and leaves an end note. Catches a message format the two halves disagree on.

`src/touch_id.rs` needs a finger, so no automated test covers it. The sheet rows of the table above check it by hand.

## 5. Cost

An approved request costs one touch, about a second of your time, plus one socket round trip, a directory listing, and scrypt at the vault-key plan's work factor 10 for each store file, normally one, a few milliseconds in all. A change adds one encryption at the same work factor. The agent decrypts the files on every request rather than caching them by name, which immutable files would allow, because a cache would keep plaintext in memory and the files cost a millisecond each. Today's read costs typing the passphrase plus about 300 ms of scrypt. A command that prompts still runs the 300 ms once, on the key file, and starting the agent after it adds a process start and the agent's `canEvaluatePolicy` call, well under the 2 seconds the command waits. The agent idles in a sleeping thread between requests and holds a key file's text, normally under 200 bytes.

## 6. Open questions

Only § 6.5 is open, and it waits on a prototype. Questions 6.1 to 6.4 are decided, and § 2 is written for those decisions.

### 6.1 What the agent holds

Decided: the vault key, from the [vault-key plan](../vault-key/readme.md), which ships first. The agent serves both reads and changes, each with a touch, so the passphrase is in memory only during a prompt. In this project the key sits in protected memory (§ 2.7). The Secure Enclave mode in § 8 waits for the signed app.

### 6.2 When it locks

Decided: a session ends when the vault key expires, 21 days after the key was made, whatever time the session started. Any passphrase prompt rotates a key 14 or more days old (vault-key plan § 2.5), so expiry never forces a prompt within 7 days of the last one on a Mac. A restart ends it too, because the key is only in memory. There is no idle timeout and no locking on sleep or the screen lock, because the touch for every request is the guard. `multipass lock`, and declining or timing out an unexpected Touch ID sheet, end it too.

### 6.3 Who may read the unlocked store

Decided: a Touch ID or Apple Watch approval through LocalAuthentication for every read and every change, as § 2.8 describes, so no program running as you, AI coding agents included, can use the store without your physical approval. One approval covers one request, with no grace period, and declining ends the session. When neither Touch ID nor a watch is available, as with the lid closed, the command asks for the passphrase. The directory check and the peer check stay as the first gate.

### 6.4 How it starts

Decided: on demand, with automatic restart. Any command that has to ask for the passphrase also starts a fresh agent, the prompt says why it asked when a session has ended, `multipass status` shows the state, and `multipass lock` ends it. There is no `multipass unlock`, because it would add nothing that any command does not already do (§ 3). Over SSH, or wherever `canEvaluatePolicy` fails, no agent starts, and every command prompts as today. `MULTIPASS_NO_AGENT=1` keeps the prompt on every command.

### 6.5 Touch ID from the detached agent

The agent calls `setsid` and runs without a terminal. Whether LocalAuthentication shows its sheet for such a process, started from a command in your login session, and whether `canEvaluatePolicy` fails cleanly for one started where no one can touch the sensor, is unverified. Owner: the implementer, with a prototype of `src/touch_id.rs` before this plan goes `ready`. If the sheet does not appear for a detached process, the agent skips `setsid` and the implementer records what closing the terminal then does. The vault-key plan does not wait on this.

## 7. Background

- `ssh-agent` holds private keys and signs for its clients, so a key never leaves it. It also checks each client with `getpeereid` and, on macOS, denies debugger attachment with `PT_DENY_ATTACH`. multipass cannot copy the signing model, because decrypting the store means handing the client its text, but it copies the socket checks and the hardening.
- `ssh-add -c` asks for a confirmation before each use of a key, through a dialog program. That is the click-to-allow design § 3 rejects. A touch is the physical form of the same idea.
- The age specification (C2SP's `age.md`) requires a fresh file key per file, a fresh payload nonce per file, and a fresh scrypt salt per stanza and file. That is why a save needs the secret the store is encrypted under, and why the vault key exists.
- On macOS, a process running as you cannot read another process's memory without a debugger entitlement, and `PT_DENY_ATTACH` refuses even a debugger. Root, and code running in the kernel, are not bound by either.

## 8. The Secure Enclave mode, with the Mac app

This section designs a second way for the agent to hold the vault key, for when the signed `Multipass.app` from the passkeys plan exists. It ships with that app, not in this project. In this mode the agent keeps only a copy of the vault key encrypted to a Secure Enclave key, and the enclave refuses to decrypt it without a touch. A dump of the agent's memory then yields only ciphertext, and the touch is enforced in hardware rather than by a check root could skip.

### 8.1 How it works

1. A command that prompted starts the agent, as § 2.1 describes, except that when `Multipass.app` is installed it starts the app's signed helper, `Multipass.app/Contents/MacOS/multipass-agent`, instead of `multipass __agent`. It still passes the vault key on the helper's stdin.
2. The helper creates a new P-256 key in the Secure Enclave with `SecKeyCreateRandomKey`, with `kSecAttrTokenIDSecureEnclave`, `kSecAttrIsPermanent` set to false, and an access control of `.biometryCurrentSet` and `.privateKeyUsage`. The key is never saved: the private half lives only in the enclave, the helper holds a `SecKey` reference, and the key is gone when the helper exits, so a restart still ends the session.
3. It encrypts the vault key to that key's public half with `SecKeyCreateEncryptedData` and `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM`, then wipes the plaintext. From then on it holds only the wrapped blob and the key reference.
4. For each request, the helper calls `SecKeyCreateDecryptedData` on the blob, passing an `LAContext` with the request's reason, such as `read github.com`, through `kSecUseAuthenticationContext`. The enclave demands the touch before it decrypts. The helper uses the plaintext vault key for that one request, through the same Rust store code, then wipes it.
5. A cancelled or failed touch ends the session, as in § 2.8. The enclave's touch replaces the agent's own `evaluatePolicy` call, because a software check beside a hardware one adds nothing.

The socket, the messages, the one-entry rule, and the end rules stay as § 2.4 to § 2.9 describe, so the CLI's client half changes only in which program it starts and which executable its peer check accepts: the helper, checked by its path inside the app and its code signature.

### 8.2 Why this shape

- **`SecKeyCreateEncryptedData` rather than CryptoKit.** It does the whole ECIES construction, the ephemeral key, the key agreement, the X9.63 key derivation, and AES-GCM, in one documented call each way. CryptoKit's `SecureEnclave.P256.KeyAgreement` offers only the key agreement, so the helper would have to assemble the rest by hand, which is more code to get wrong.
- **A non-permanent key.** Nothing about the session touches disk or the Keychain, so a restart ends it as it does today, and there is no item to clean up or leak.
- **The agent moves into the app as a helper.** The enclave key's access control, and probably the enclave itself, need a binary signed with the app's team and entitlements, which the CLI built by `cargo install` is not. A helper inside the app gets the signature, and keeping the socket protocol means the CLI needs no new code path beyond starting it. The alternative, the CLI asking the app over XPC, would need an XPC client in Rust through `unsafe` code for no gain.

### 8.3 What it exposes, under each mode

| Who | Protected memory (§ 2.7) | Secure Enclave mode |
| --- | --- | --- |
| Root, or a kernel exploit | Copies the vault key at any time in the session, and can skip the software check | Finds only the wrapped blob between requests. It must wait for an approved request and copy the plaintext in the moment it exists, or ask the enclave, which still wants a touch. It can still capture the passphrase at the next prompt, as today. |
| A memory dump or crash report | No core file, but a dump by root holds the key | Holds only ciphertext |
| A future quantum computer | Nothing to attack: everything is symmetric | P-256 ECIES now sits in the session path, and a large enough quantum computer could break it given the blob and the public key. Both live only in the helper's memory, never on disk or in sync, so there is nothing to record now and break later. The key file stays passphrase-only age, the quantum-safe copy of the vault key. |
| A program running as you | Needs a touch per request | The same, enforced by the enclave |

### 8.4 What it needs

- **Signing and entitlements.** A Developer ID or App Store signature on the helper, and whatever entitlement the enclave key needs, probably `keychain-access-groups`. The passkeys plan already distributes the app through TestFlight, so the helper ships inside that build.
- **The app sandbox.** TestFlight and App Store builds of a Mac app must be sandboxed. A sandboxed helper may not be able to bind a socket in `~/.multipass/agent/` or read a store package outside its containers. The socket would then move to the app group container, and the store to the iCloud container that the passkeys plan already uses.
- **The Rust store code** as a library, which the passkeys plan's XCFramework already builds.

### 8.5 Unverified, for the app's prototype

The passkeys plan's prototype answers these before this mode is built:

1. Can a sandboxed, TestFlight-signed helper create a non-permanent Secure Enclave key with `.biometryCurrentSet`, and with which entitlements?
2. Does `SecKeyCreateDecryptedData` ask for a touch on every call when each call gets a fresh `LAContext` whose `touchIDAuthenticationAllowableReuseDuration` is 0?
3. Can the CLI start the helper from inside the app bundle and pass it the vault key on stdin, and does the sandbox allow that?
4. Where can the helper bind its socket so that the unsandboxed CLI can reach it, and can it read the store at `MULTIPASS_STORE`?
5. Does an Apple Watch approval work for an enclave key's `.biometryCurrentSet` access control, or only Touch ID? If only Touch ID, this mode loses the watch, and the plan records whether that is acceptable.
