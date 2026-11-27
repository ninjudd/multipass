---
status: draft
priority: now
---

# Session unlock

After you type the passphrase once, a background agent keeps the store unlocked, and later commands that read it ask for a touch of Touch ID or a press on an Apple Watch instead of the passphrase, until the agent locks.

## 1. Problem

multipass keeps every entry in one age file encrypted under a passphrase. Every command calls `open` in `src/main.rs`, which asks for the passphrase on `/dev/tty` and decrypts the store with `Store::load`. Commands that change the store then re-encrypt it with `Store::save`, which picks a fresh scrypt salt and file key each time, as the age format requires. Nothing outlives the command, so no key stays in memory once it exits.

The cost is a prompt and about 300 ms of scrypt at work factor 18 on every command. Looking up a username, then a password, then a one-time code means typing the passphrase three times. That pushes people toward a short passphrase, the one thing that protects the store, or away from multipass for anything they use often.

The prompt also guarantees something a fix must keep: only a person who knows the passphrase can read the store. A program running as you cannot, and that includes an AI coding agent that runs shell commands for you. Even one that fakes a terminal with `expect` still lacks the passphrase.

## 2. Solution

Whenever a command has to ask for the passphrase, it also starts a background agent, `multipass __agent`, and hands it the store's file key. The agent holds only that file key and the header it belongs to. It listens on a Unix socket in a 0700 directory, checks that each client runs as the same user, and answers one useful request: it asks you to approve with Touch ID or an Apple Watch, then reads the store file from disk, decrypts it with the file key, and returns the store text. Every read asks again, so no program can read the store without your finger on the sensor, and declining a request locks the agent. `get`, `list`, and `otp` ask the agent first, and fall back to the passphrase prompt when no agent runs or Touch ID is not available. Commands that save still ask for the passphrase, because the age format forbids reusing a file key or a salt, so every save needs scrypt and the passphrase. The agent locks by exiting: after 60 minutes without a request, 12 hours after it started, when the Mac sleeps, when the screen locks, when you decline a request, and on `multipass lock`. The next command then asks for the passphrase, says why, and starts a fresh agent. `multipass status` tells you whether the store is unlocked and when it will lock.

Starting an agent without being asked is safe only because every read needs your touch (§ 2.7). Without that, a session that starts on its own would let any program running as you read the store silently whenever you had used multipass recently.

This design depends on the answers to § 6.1 and § 6.2. Until those are settled, this plan stays a draft.

### 2.1 How a session starts

1. You run any command, such as `multipass get github.com`, and no agent answers for this store, or `open` skips the agent (§ 2.4). The command asks for the passphrase on `/dev/tty`, as today. When an earlier agent for this store has locked, the prompt says why, such as `Passphrase (locked after 60 idle minutes): ` (§ 2.4).
2. `open` reads the store file and calls `age::unlock`, which runs scrypt, unwraps the file key, and checks the header MAC. It then decrypts the payload with `age::decrypt_unlocked`, and the command runs as today. A wrong passphrase fails here, and no agent starts.
3. When the command succeeds, and neither `MULTIPASS_NO_AGENT` nor `SSH_CONNECTION` is set, it starts `multipass --store <path> __agent` as a child, with stdin and stdout piped and stderr discarded. It writes the start message (§ 2.6) to the child's stdin and closes it. The file key goes only to a process the command started itself, never over the socket.
4. The agent calls `setsid`, so closing the terminal does not end it. It denies debugger attachment and core dumps (§ 2.9), and asks LocalAuthentication whether Touch ID or an Apple Watch can approve requests (§ 2.7). When neither can, it exits, and no session starts. Otherwise it checks the file key against the store on disk, binds its socket (§ 2.5), removes the store's lock note (§ 2.4), writes `ready` to stdout, and closes stdout.
5. The command waits up to 2 seconds for `ready` and then exits. It says nothing about the agent either way, so a failed start costs nothing but the next prompt.

### 2.2 How a read works while unlocked

1. You run `multipass get github.com`. `open` connects to the socket for this store, checks the directory and the peer (§ 2.5), and sends `read`.
2. The agent reads the store file. When the header differs from the one it holds, because another machine, the passkeys extension, or a save replaced the file, it replies `stale` and exits, without asking you anything.
3. Otherwise the agent asks for approval (§ 2.7), and macOS shows its Touch ID sheet: "multipass is trying to read your multipass store." When you approve, the agent decrypts the payload with the file key and replies with the store text. When you cancel, or leave the sheet for 60 seconds, it replies `denied` and exits. When Touch ID and the watch are both unavailable at that moment, such as with the lid closed and no watch in reach, it replies `unavailable` and stays unlocked.
4. `open` parses the text with `Store::from_text`, and the command goes on as today. On `denied`, the command fails with `the request was not approved`, and the next command asks for the passphrase. On `stale` or `unavailable`, or when no agent answers, `open` asks for the passphrase and the session starts as § 2.1 describes.

### 2.3 How a save works

1. `init`, `add`, `rm`, `otp --set`, `otp --clear`, and `passwd` ask for the passphrase and decrypt the store, as today, whether or not an agent runs. They ask for no Touch ID approval, because the passphrase already shows a person is there.
2. `Store::save` encrypts with a fresh salt and file key, as today, and now returns the new header and file key that `age::encrypt` produced.
3. The command sends `status` and then `lock` to any agent for this store, which ends the old session, and starts a fresh agent with the new header and file key, as § 2.1 steps 3 to 5 describe. The fresh agent keeps the old agent's absolute deadline, which `status` reported, and starts a new idle timer.

### 2.4 Commands, prompts, and settings

| Name | What it does |
| --- | --- |
| `multipass status` | Prints `unlocked; locks after 60 idle minutes, and at 22:15 at the latest`, with the real numbers, or `locked`, followed by the reason from the lock note when there is one, such as `locked: the screen locked at 13:05`. It asks for nothing. |
| `multipass lock` | Sends `lock` to the store's agent, and prints `Locked`, or `Not unlocked` when no agent answered. |
| The lock note | When an agent locks, it writes `<hash>.locked` beside its socket, holding the reason and the time, such as `idle 60 1764160000`. The note holds no secret. The prompt and `status` read it, and a starting agent removes it. |
| The prompt | `Passphrase: ` when there is no lock note, and otherwise `Passphrase (<reason>): `, such as `locked after 60 idle minutes`, `the screen locked`, `the Mac slept`, `you declined a request`, `the store changed`, `12 hours passed`, or `locked by multipass lock`. |
| `MULTIPASS_NO_AGENT=1` | `open` never asks an agent and no command starts one, so every command prompts as today. |
| `MULTIPASS_IDLE_MINUTES` | Sets the idle timeout for agents started while it is set, from 1 to 720. The default is 60. |
| `SSH_CONNECTION` | When it is set, `open` skips the agent and no command starts one. Nobody at the far end of SSH can touch the Mac's sensor, so asking would only leave a sheet on the Mac's screen until it times out and locks the session. |

None of the three environment variables carries a secret, so the rule against secrets in the environment does not apply to them.

### 2.5 The socket and who may connect

| Part | Value |
| --- | --- |
| Directory | `~/.multipass/agent/`, created with mode 0700 by the existing `create_private_dir`. It stays under `$HOME` even when `MULTIPASS_STORE` points into a synced folder, so the socket never syncs. |
| Socket | `<hash>.sock`, where `<hash>` is the first 16 hex digits of the SHA-256 of the canonical store path. Each store gets its own agent, so `--store` keeps working. The path is public, so hashing it is not cryptography on a secret. |
| Directory check | Before every connect and bind, the client and the agent check that the directory belongs to the current user and has mode 0700, using `std::os::unix::fs::MetadataExt`. Otherwise they refuse to use it and name the directory. |
| Peer check | The agent calls `getpeereid` on each accepted connection and closes any whose user ID differs from its own. The client checks the agent the same way before it sends `read`. This is the first gate, and the touch in § 2.7 is the second. |
| Platforms | macOS only, because Touch ID approval is macOS's and CI runs only there. On other systems no agent starts, and every command prompts as today. |

The agent serves one connection at a time. It gives a client 2 seconds to send its request, so a client that stalls cannot hold it, and waits up to 60 seconds for your approval. Other clients wait their turn.

### 2.6 Messages

Every message is one line of ASCII, sometimes followed by a counted run of bytes. No reply names an entry or quotes the store outside the `read` reply, and the agent writes no log.

| Message | Path | Reply |
| --- | --- | --- |
| `start <idle-seconds> <deadline-unix> <n>\n`, then `n` bytes: the header through the MAC line, then the 16-byte file key | The agent's stdin, from the process that started it | `ready\n` on stdout, or exit with status 1 |
| `read\n` | Socket | `ok <n>\n` then `n` bytes of store text, or `stale\n`, `denied\n`, or `unavailable\n` |
| `status\n` | Socket | `unlocked <idle-seconds-left> <deadline-unix>\n` |
| `lock\n` | Socket | `ok\n`, then the agent writes its lock note, removes its socket, and exits |

The agent never sends the file key, the keys derived from it, or the header MAC. No message carries the passphrase. `status` and `lock` need no approval: the first reveals only that an agent runs, and the second can only end it.

### 2.7 Approval with Touch ID or an Apple Watch

| Part | Value |
| --- | --- |
| Framework | LocalAuthentication's `LAContext`, called from `src/touch_id.rs` through the Objective-C runtime, as `src/clipboard.rs` calls AppKit. It needs no Keychain item and no entitlement, so it works from an unsigned command-line program. |
| Policy | `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch`: a finger on Touch ID, or a double press on a paired Apple Watch. Not `LAPolicyDeviceOwnerAuthentication`, which falls back to the login password, because a program that knows or captures that password could type it. |
| At start | `canEvaluatePolicy` must succeed, or the agent exits and no session starts (§ 2.1 step 4). |
| Each `read` | A fresh `LAContext` and one `evaluatePolicy` call, with the reason `read your multipass store`. One approval covers one `read`, with no grace period. |
| Approved | The agent replies with the store text. |
| Cancelled, failed, or 60 seconds with no answer | The agent replies `denied`, calls `invalidate` on the context, writes its lock note, and exits. A request you did not expect means something else asked, so the agent stops serving anyone. |
| Unavailable at that moment | `LAErrorBiometryNotAvailable`, `LAErrorBiometryLockout`, or no watch in reach: the agent replies `unavailable` and stays unlocked, and the command asks for the passphrase. |

The reply arrives in an Objective-C block on a queue LocalAuthentication owns. `src/objc.rs` builds that block by hand, a global block with no captured variables, and the block hands the result to the waiting agent thread through a `std::sync::mpsc` channel.

### 2.8 When it locks

Locking means the agent writes its lock note, removes its socket, and exits, so the file key leaves memory with the process. Locking costs you one passphrase prompt on the next command, which starts a fresh session. A thread wakes every 5 seconds and locks when any of these holds:

| Trigger | How the agent sees it |
| --- | --- |
| Idle timeout | 60 minutes since the last approved `read`, by default, or `MULTIPASS_IDLE_MINUTES`. |
| Absolute deadline | 12 hours after the session started, however busy it is. |
| Sleep | On macOS, `Instant` stops during sleep and `SystemTime` does not. When the wall clock moves more than 30 seconds further than `Instant` between ticks, the machine slept. A change to the clock can trigger it too, which only locks early. |
| Screen lock | The thread runs `/usr/sbin/ioreg -n Root -d1 -a` and locks when `IOConsoleLocked` reads true. |
| A declined request | § 2.7. This one is not on the thread: the agent exits as it replies `denied`. |
| `multipass lock` | § 2.4. |
| A changed store | The store file no longer starts with the held header (§ 2.2 step 2). |

`ioreg` is a system tool, run the way `src/tty.rs` already runs `/bin/stty`.

### 2.9 What session unlock exposes

An agent trades a passphrase per command for a touch per command, and holds the file key in memory between them. The touch keeps what the prompt guaranteed: no program can read the store without a person at the Mac. What it loses is the knowledge factor. A person at your unlocked Mac with an enrolled finger, or wearing your watch, can read the store without knowing the passphrase until the agent locks. Because sessions start on their own, everyone who uses multipass on a Mac with Touch ID or a watch has such a window after each use, unless they set `MULTIPASS_NO_AGENT=1`.

| Who | Without an agent | With an unlocked agent |
| --- | --- | --- |
| Another user on the Mac | Cannot read the store | Cannot connect: the directory check and the peer check refuse them |
| An AI coding agent running commands as you | Cannot answer the `/dev/tty` prompt without the passphrase, even through a fake terminal | Each `multipass get` it runs puts a Touch ID sheet on your screen. Nothing it can do presses the sensor or the watch, and declining locks the agent. It cannot start a session either, because starting one takes the passphrase. |
| Malware running as you, reading | Must trojan the binary and wait for a prompt | The same as an AI agent, with one opening: it can send its `read` just before one of your own commands, so your touch approves its request. Your own command then asks a second time, which is the sign. Declining that second sheet locks the agent. |
| Malware running as you, writing | Cannot write a valid store without the passphrase | The same, because saves still need the passphrase |
| Malware running as you, posing as the agent | Nothing to pose as | Can bind the socket while no agent runs and answer `read` with fake store text. It never receives the file key, which crosses only a pipe to a child the command started. |
| A person at your unlocked Mac | Needs the passphrase | Needs an enrolled finger or your watch, until the agent locks. The screen lock trigger ends this when the Mac locks. |
| Root, or a debugger | Can read the passphrase from a command's memory while it runs | The agent denies debugger attachment with `ptrace(PT_DENY_ATTACH)`, so a debugger fails, but root can still read the file key from memory without any touch. The file key opens this version of the store, not the passphrase or any later version. |
| A crash report or core dump | Could hold the passphrase from a running command | The agent sets `RLIMIT_CORE` to 0, so it leaves no core file |

The README says this plainly, names `MULTIPASS_NO_AGENT=1` for anyone who wants a prompt every time, and shows `multipass lock` for ending a session early.

### 2.10 Neighbors: passkeys and the clipboard

- **The passkeys Keychain item.** The passkeys plan's extension keeps the passphrase in a Keychain item that only its own access group can read. The CLI is not signed into that group, so the agent cannot use the item, and the extension cannot use the agent. They stay independent, though both now use Face ID or Touch ID. When the extension saves a new passkey, the store's header changes, the agent replies `stale`, and the next command asks for the passphrase. The passkeys plan's § 2.3 says the CLI "still asks for the passphrase every time"; this project changes that sentence to point here.
- **`--clip`.** `get --clip` and `otp --clip` are a separate feature, in pull request #9. They copy the value through AppKit's `NSPasteboard`, marked current-host-only and concealed. A detached `multipass __clear-clipboard <count>` process clears the clipboard 30 seconds later, and only if the pasteboard's change count still equals `<count>`. `--clip` reads the value through `open`, so it asks for the same approval as `get`. The clearing process never touches the store, so it does not depend on the agent, which may lock before it runs.

### 2.11 Changes by file

This table assumes pull request #9, which adds `--clip` and `src/clipboard.rs`, merges first.

| File | Change |
| --- | --- |
| `src/age.rs` | `encrypt` also returns an `Unlocked { header: Vec<u8>, file_key: [u8; 16] }`. New `unlock(passphrase, data) -> Result<Unlocked, Error>` does the header half of `decrypt`, and new `decrypt_unlocked(&Unlocked, data)` checks that `data` starts with exactly `header` and decrypts the payload. `decrypt` becomes `unlock` then `decrypt_unlocked`, so the payload code exists once. |
| `src/store.rs` | `Store::save` returns the `Unlocked` from `encrypt`. New `Store::from_bytes(Vec<u8>)` runs the UTF-8 check and `from_text` that `decrypt` runs today, and `decrypt` calls it. New `Store::unlock(path, passphrase)` returns the store with its `Unlocked`, for the command to hand to a new agent. |
| `src/agent.rs` | New. The agent half: reads the start message from stdin, binds the socket, answers `read`, `status`, and `lock`, runs the lock thread in § 2.8, and writes the lock note. It asks for approval through an `Approver` trait, which `touch_id::TouchId` implements and tests replace with a fake. The client half: `read`, `status`, `lock`, `lock_note`, and `start`, which spawns an agent and writes the start message. The socket path, the lock note's path, and the directory check live here, shared by both halves. The lock decision is a pure function of the deadlines, the two clock readings, and the screen state, so tests can drive it. |
| `src/touch_id.rs` | New `unsafe` module. Links `LocalAuthentication.framework`, and wraps `canEvaluatePolicy:error:`, `evaluatePolicy:localizedReason:reply:`, and `invalidate` in a safe `TouchId::available()` and `TouchId::approve(reason, timeout) -> Approval`, where `Approval` is `Approved`, `Denied`, or `Unavailable`. |
| `src/objc.rs` | New `unsafe` module. The typed `objc_msgSend`, class, selector, and `NSString` helpers move here from `src/clipboard.rs`, so the clipboard and Touch ID share one copy, and it adds the global block that carries `evaluatePolicy`'s reply. |
| `src/clipboard.rs` | Calls the helpers in `src/objc.rs` instead of defining its own. Its module comment stops calling it the program's only `unsafe` code. |
| `src/sys.rs` | New `unsafe` module, built like `src/clipboard.rs`: `unsafe extern "C"` declarations for `getuid`, `getpeereid`, `setsid`, `ptrace(PT_DENY_ATTACH)`, and `setrlimit(RLIMIT_CORE)` behind safe wrappers, under `#[cfg(target_os = "macos")]`. The standard library offers no stable call for any of them at `rust-version = "1.85"`. |
| `src/main.rs` | Adds `status`, `lock`, and the hidden `__agent` command, named like `__clear-clipboard`. `open` asks the agent for the store unless § 2.4's variables say not to, fails on `denied`, and otherwise prompts with the reason from the lock note, then starts an agent once the command succeeds. Saving commands call a new `open_to_save`, which always prompts, and replace any agent with a fresh one after `save`. Updates `USAGE`. |
| `README.md` | Documents sessions: the touch for each read, when a session locks, `status`, `lock`, the three variables in § 2.4, and § 2.9's trade in a few sentences. Changes "Every command asks for the passphrase" and removes "Session unlock" from "Not built yet". |
| `AGENTS.md` | Changes the rule "Apple's system frameworks count like the standard library", which says `src/clipboard.rs` "holds the program's only `unsafe` code", so it names `src/objc.rs`, `src/clipboard.rs`, `src/touch_id.rs`, and `src/sys.rs` as the modules that hold `unsafe` code, each behind a safe interface, with a comment on each call saying what it requires of its arguments. Adds the agent's rules: the file key reaches an agent only through the stdin of a child the CLI started; the agent sends store text only after an approval for that one request; it never sends a key or the passphrase. |
| `docs/projects/passkeys/readme.md` | § 2.3's sentence about the CLI changes as § 2.10 says. |

## 3. Why this design

- **A touch for every read.** The worry this design answers is a program, an AI coding agent above all, that runs `multipass get` as you while the store is unlocked. Every way to tell such a program from you in software fails, because it runs as you, can start from your terminal, and can fake a terminal or click a dialog. A finger on Touch ID or a press on the watch is physical, so it is the one check no program can pass. Asking on every read, with no grace period, means a program can never ride on an approval you gave a moment earlier.
- **Sessions start on their own.** An explicit `unlock` command would make you keep track of whether the last session has expired, and people are bad at keeping track of time. Starting a session from any command that already had to prompt costs you nothing extra, and the prompt's reason tells you why it asked again. The case for an explicit `unlock` was safety: a session you did not ask for widens the window. The touch for every read closes that window, because a running agent no longer lets anything read without you. So `unlock` would add nothing that `multipass list` does not already do, and the plan leaves it out.
- **Declining locks the agent.** A sheet you did not expect is evidence that something else is asking. Locking stops a program from asking again and again until a reflexive touch approves it, and the cost is typing the passphrase once after a mistaken cancel.
- **Unavailable falls back to the passphrase.** With the lid closed and no watch, the passphrase prompt still proves a person is there, so it is a safe fallback. A cancelled sheet does not fall back, because that would let a program turn your "no" into a second chance.
- **SSH skips the agent.** The SSH server sets `SSH_CONNECTION`, and a client could ignore it, so the check is only a courtesy: a client that ignores it gets a sheet on the Mac's screen like any other. It keeps a remote session from leaving a sheet nobody can answer, and from locking the session at the desk when that sheet times out.
- **The agent holds the file key, not the passphrase.** The age specification says a file key "MUST NOT be reused across multiple files", and that "A new salt MUST be generated for each stanza and each file". So a key derived from the passphrase can read one version of the store but never write the next one, and an agent that saves must hold the passphrase itself. § 6.1 weighs the two.
- **The agent reads the file on every request.** It never caches the decrypted store, so plaintext sits in its memory only while it answers, and it notices a store changed by another machine at once rather than serving an old copy. Decrypting a few kilobytes of ChaCha20-Poly1305 takes well under a millisecond.
- **The key crosses a pipe, never the socket.** Any process running as you can bind the socket path while no agent runs. If a command sent the key over the socket, such a process could pose as the agent and collect it. A pipe to a child the command started itself offers no such opening.
- **Locking means exiting.** One rule covers every trigger, and no locked process stays behind. The lock note outlives the process only to explain the next prompt.
- **Sleep is seen through the clocks.** Hearing about sleep from macOS directly needs IOKit's power notifications and a run loop. Comparing `Instant` with `SystemTime` needs only the standard library, and errs toward locking early.
- **Reuse.** The header code in `age::decrypt` moves into `age::unlock` and the payload code into `age::decrypt_unlocked`, and `decrypt` calls the two, so the agent and the prompt decrypt through the same lines. The Objective-C helpers move out of `src/clipboard.rs` into `src/objc.rs`, so Touch ID does not repeat them. The directory comes from `create_private_dir`, and the socket's hash from `crypto::sha256`.
- **Rejected: an explicit `multipass unlock`.** See "Sessions start on their own" above.
- **Rejected: `eval $(multipass agent)` in each shell, as `ssh-agent` does.** It needs a line in your shell setup, and gives each terminal its own agent, so a second window asks again.
- **Rejected: a launchd agent started at login.** It needs an install step, and it would still need the passphrase from some command before it could read anything, so it saves nothing over starting on demand.
- **Rejected: binding the agent to the terminal that started it.** Anything started from that terminal inherits it, an AI agent included, and a program can open a terminal of its own.
- **Rejected: a click-to-allow dialog.** A program with accessibility or screen-control access can click it, and people learn to click it without reading.
- **Rejected: any process running as you, with no approval.** It reads silently, so an AI agent running as you could read every entry while the store is unlocked.
- **Rejected: holding the passphrase's HMAC state.** The precomputed HMAC-SHA-256 inner and outer states of the passphrase would let the agent run scrypt for any salt without the passphrase's text. But they let an attacker test guesses at SHA-256 speed instead of scrypt speed, which is worse than holding the passphrase.
- **Rejected: a socket path in an environment variable, as `SSH_AUTH_SOCK` does.** A fixed socket path per store lets every terminal find the agent without shell setup.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| With no agent running, `multipass get github.com` | Asks `Passphrase: `, prints the secret, and an agent is running afterwards |
| `multipass get github.com` again, and touch the sensor | No passphrase prompt. The Touch ID sheet appears, then the secret prints. |
| `multipass get github.com` a third time, right away | The sheet appears again: one touch covers one read |
| `multipass get github.com`, and cancel the sheet | `get` fails with `the request was not approved`, and the agent has exited. The next `get` asks `Passphrase (you declined a request): `. |
| `multipass get github.com`, and leave the sheet for 60 seconds | The same as cancelling |
| While unlocked, run `multipass get github.com` from a script started with no terminal | The Touch ID sheet appears, and nothing prints until someone touches the sensor |
| Over SSH, `multipass get github.com` while an agent runs at the desk | Asks for the passphrase, shows no sheet on the Mac, and the desk's agent keeps running |
| `MULTIPASS_NO_AGENT=1 multipass get github.com` twice | Both ask for the passphrase, and no agent starts |
| With the lid closed, an external display, and no Apple Watch, `multipass get github.com` while unlocked | `get` asks for the passphrase, and the agent stays unlocked |
| A wrong passphrase at any prompt | Fails with `wrong passphrase, or the store is damaged`, and no agent starts |
| `multipass add x` while unlocked, then `multipass get x` and touch the sensor | `add` asks for the passphrase and shows no sheet. `get` prints the secret of `x`, so the fresh agent holds the new key. |
| Replace the store file with a copy saved elsewhere, then `multipass list` | No sheet appears. `list` asks `Passphrase (the store changed): `. |
| `MULTIPASS_IDLE_MINUTES=1 multipass list`, wait 70 seconds, then `multipass list` | The second `list` asks `Passphrase (locked after 1 idle minute): ` |
| `pmset sleepnow` while unlocked, wake the Mac, then `multipass list` | `list` asks `Passphrase (the Mac slept): ` |
| Lock the screen while unlocked, unlock it, then `multipass list` | `list` asks `Passphrase (the screen locked): ` |
| `multipass status` while unlocked, then `multipass lock`, `multipass lock`, `multipass status` | `unlocked; locks after …`, then `Locked`, then `Not unlocked`, then `locked: locked by multipass lock` |
| `chmod 755 ~/.multipass/agent`, then `multipass list` | Refuses to use the agent, names the directory, and asks for the passphrase |
| `lldb -p <agent pid>` | Attaching fails |
| `ps -o args= -p <agent pid>` | Shows `multipass --store <path> __agent` and nothing secret |

Tests that must fail before the change and pass after it:

- **`age::unlock` then `decrypt_unlocked`** decrypts each `testdata/reference-*.age` fixture, so the split cannot change what `decrypt` accepts. Catches an off-by-one in where the header ends.
- **`decrypt_unlocked` rejects a file whose header differs by one byte** from the held one, and a file encrypted again under the same passphrase. Catches an agent that serves a stale key against a new file.
- **The `Unlocked` that `encrypt` returns decrypts the file `encrypt` wrote.** Catches a save that hands the fresh agent the old key.
- **The start message** round-trips through its writer and reader, and the reader rejects a short key, a missing count, and trailing bytes. Catches a key that arrives truncated.
- **The approval gate**, with a fake `Approver` that counts its calls and returns a scripted answer. Two `read`s call it twice. `Denied` sends `denied`, sends no store bytes, writes the lock note, and the agent exits. `Unavailable` sends `unavailable` and the agent keeps serving. A stale store sends `stale` without calling it. Catches an agent that sends text before approval, a grace period that slips in, and a cancel that does not lock.
- **The lock decision**, table-driven over the idle deadline, the absolute deadline, the two clock readings, and the screen state. It covers each trigger and the 30-second sleep threshold on both sides. Catches a session that never locks after sleep.
- **The lock note and the prompt.** Each reason the agent writes turns into its prompt text, with `1 idle minute` and `60 idle minutes`. A missing note, and a note with an unknown reason, both give `Passphrase: ` rather than an error. Catches a prompt that blames the wrong cause.
- **The agent switches in `open`**, as a pure function of `MULTIPASS_NO_AGENT` and `SSH_CONNECTION`. Catches an opt-out that still starts an agent.
- **The directory check** refuses a directory with mode 0755 and accepts 0700, in a temporary directory. Catches a socket other users could reach.
- **An agent end to end**, in a temporary directory at work factor 10 with a fake `Approver` that approves: start it with a store's `Unlocked`, and `read` returns the store text, `status` reports the idle time left, rewriting the store makes `read` return `stale`, and `lock` removes the socket and leaves a lock note. Catches a message format the two halves disagree on.

`src/touch_id.rs` needs a finger, so no automated test covers it. The sheet rows of the table above check it by hand.

## 5. Cost

An approved read costs one touch, about a second of your time, plus one socket round trip, one file read, and a ChaCha20-Poly1305 decryption of a few kilobytes, a few milliseconds in all. Today's read costs typing the passphrase plus about 300 ms of scrypt. A command that prompts still runs scrypt once, and starting the agent after it adds a process start and the agent's `canEvaluatePolicy` call, well under the 2 seconds the command waits. Every save still runs scrypt twice, once to open and once to save, as today. The lock thread spawns `ioreg` every 5 seconds. The implementer measures the agent's CPU time over an hour with `ps -o time=` and records it in § 7, and moves the poll to 10 seconds if it exceeds 1% of a core. Between requests the agent holds a header and a 16-byte key.

## 6. Open questions

Questions 6.1 and 6.2 wait on the user, and 6.5 waits on a prototype. Questions 6.3 and 6.4 are decided. § 2 is written for each recommended answer.

### 6.1 What the agent holds

Recommended: the file key and header only, so reads need a touch and saves still need the passphrase. The alternative is to hold the passphrase, so saves need only a touch too, and the agent runs scrypt and writes the store itself. With a touch on every request, the two differ in three ways:

- **Who can change your entries.** With the file key only, changing the store takes the passphrase, which no program has. With the passphrase held, it takes a touch, and the one opening in § 2.9 applies: a program that times its request just before one of yours gets your touch. A stolen read leaks secrets, but a stolen save can delete or replace them silently, and only a backup brings them back.
- **What sits in memory.** With the passphrase held, it stays in the agent for the whole session. Root could read it there, and it opens every copy of the store, past and future, until you change it. Root could also capture the passphrase at your next prompt, so this matters less than it sounds, but the file key opens only the current copy.
- **How often you type.** Saves are rare in a store of recovery codes and seed phrases, so the file key costs a prompt on the occasional `add`, `rm`, or `otp --set`. The passphrase would end those prompts, and adds a `write` message, a check that the file has not changed since the read, and a second sheet reason, such as `change your multipass store`.

Owner: the user.

### 6.2 When it locks

Recommended: lock 60 minutes after the last read, 12 hours after the session started at the latest, and whenever the Mac sleeps, the screen locks, you decline a request, or you run `multipass lock`. `MULTIPASS_IDLE_MINUTES` changes the 60, from 1 to 720. Locking now costs only one passphrase prompt on the next command, and the touch already stops programs from reading, so the idle timeout no longer needs to be short. The screen lock does most of the work when you walk away. The 12 hours bounds how long a file key sits in memory on a Mac whose screen never locks. Owner: the user.

### 6.3 Who may read the unlocked store

Decided: a Touch ID or Apple Watch approval through LocalAuthentication for every read, as § 2.7 describes, so no program running as you, AI coding agents included, can read a secret without your physical approval. One approval covers one read, with no grace period. When neither Touch ID nor a watch is available, as with the lid closed or over SSH, the command asks for the passphrase. The directory check and `getpeereid` stay as the first gate.

### 6.4 How it starts

Decided: on demand, with automatic restart. Any command that has to ask for the passphrase also starts a fresh agent, the prompt says why it asked when a session has locked, `multipass status` shows the state, and `multipass lock` ends it. There is no `multipass unlock`, because it would add nothing that any reading command does not already do (§ 3). `MULTIPASS_NO_AGENT=1` keeps the old prompt on every command.

### 6.5 Touch ID from the detached agent

The agent calls `setsid` and runs without a terminal. Whether LocalAuthentication shows its sheet for such a process, started from a command in your login session, and whether `canEvaluatePolicy` fails cleanly for one started where no one can touch the sensor, is unverified. Owner: the implementer, with a prototype of `src/touch_id.rs` before this plan goes `ready`. If the sheet does not appear for a detached process, the agent skips `setsid` and the implementer records what closing the terminal then does.

## 7. Background

- `ssh-agent` holds private keys and signs for its clients, so a key never leaves it. It also checks each client with `getpeereid` and, on macOS, denies debugger attachment with `PT_DENY_ATTACH`. multipass cannot copy the signing model, because decrypting the store means handing the client its text, but it copies the socket checks and the hardening.
- `ssh-add -c` asks for a confirmation before each use of a key, through a dialog program. That is the click-to-allow design § 3 rejects. A touch is the physical form of the same idea.
- The age specification (C2SP's `age.md`) requires a fresh file key per file, a fresh payload nonce per file, and a fresh scrypt salt per stanza and file. That rules out an agent that saves with a cached key.
- `ioreg -n Root -d1 -a` prints `IOConsoleLocked` as `<false/>` on an unlocked Mac. The implementer confirms that it reads `<true/>` with the screen locked before relying on it, and records the result here.
- On macOS, `std::time::Instant` reads a clock that stops during sleep, while `SystemTime` reads the wall clock. The sleep check in § 2.8 depends on that difference, and the `pmset sleepnow` row of § 4 checks it.
