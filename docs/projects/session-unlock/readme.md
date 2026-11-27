---
status: draft
priority: now
---

# Session unlock

After you type the passphrase once, a background agent keeps the store unlocked for up to 14 days, and every later read or change asks for a touch of Touch ID or a press on an Apple Watch instead of the passphrase.

## 1. Problem

multipass keeps every entry in one age file encrypted under a passphrase. Every command calls `open` in `src/main.rs`, which asks for the passphrase on `/dev/tty` and decrypts the store with `Store::load`, and every command that changes the store runs scrypt again in `Store::save`. Nothing outlives the command, so no key stays in memory once it exits.

The cost is a prompt and about 300 ms of scrypt at work factor 18 on every command. Looking up a username, then a password, then a one-time code means typing the passphrase three times. That pushes people toward a short passphrase, the one thing that protects the store, or away from multipass for anything they use often.

The prompt also guarantees something a fix must keep: only a person who knows the passphrase can read or change the store. A program running as you cannot, and that includes an AI coding agent that runs shell commands for you. Even one that fakes a terminal with `expect` still lacks the passphrase.

## 2. Solution

This project has two parts. The first, the [vault key](vault-key/readme.md), ships first as its own plan: the passphrase unlocks a random vault key kept in a small key file beside the store, and the vault key encrypts the store, so saving needs only the vault key. The second, the rest of this plan, adds the agent.

Whenever a command has to ask for the passphrase, it opens the key file and starts a background agent, `multipass __agent`, holding only the vault key. The agent listens on a Unix socket in a 0700 directory, checks that each client runs as the same user from the same `multipass` binary, and answers two requests. A read asks you to approve with Touch ID or an Apple Watch, then decrypts the store and returns its text. An edit asks the same way, returns the text, and saves the changed text the command sends back. Every request asks again, so no program can read or change the store without your finger on the sensor, and declining a request locks the agent. So after the first prompt, `get`, `add`, `rm`, and `otp` each cost one touch, and only `passwd` and `rekey` still ask for the passphrase. A session ends after 14 days, on a restart, on `multipass lock`, or when you decline a request. The next command then asks for the passphrase, says why, and starts a fresh session. `multipass status` tells you whether the store is unlocked and until when. Over SSH, and wherever Touch ID and a watch are both unavailable, no agent starts, and every command prompts as today.

Starting a session without being asked, and keeping it for two weeks, is safe only because every request needs your touch (§ 2.8). Without that touch, such a session would let any program running as you read and rewrite the store silently.

This plan stays a draft until the prototype in § 6.5 confirms that the agent can show the Touch ID sheet.

### 2.1 How a session starts

1. You run any command, such as `multipass get github.com`, and no agent answers for this store, or `open` skips the agent (§ 2.4). The command asks for the passphrase on `/dev/tty`, as today. When an earlier session for this store has ended, the prompt says why, such as `Passphrase (the session ended): ` (§ 2.4).
2. `open` opens the key file and the store with `Store::open`, as the vault-key plan describes, and the command runs. A wrong passphrase fails here, and no agent starts.
3. When the command succeeds, and neither `MULTIPASS_NO_AGENT` nor `SSH_CONNECTION` is set, it starts `multipass --store <path> __agent` as a child, with stdin and stdout piped and stderr discarded. It writes the start message (§ 2.6) to the child's stdin and closes it. The vault key goes only to a process the command started itself, never over the socket.
4. The agent calls `setsid`, so closing the terminal does not end it. It denies debugger attachment and core dumps (§ 2.7), and asks LocalAuthentication whether Touch ID or an Apple Watch can approve requests (§ 2.8). When neither can, it exits, and no session starts. Otherwise it checks the vault key against the store, binds its socket (§ 2.5), removes the store's end note (§ 2.4), writes `ready` to stdout, and closes stdout.
5. The command waits up to 2 seconds for `ready` and then exits. It says nothing about the agent either way, so a failed start costs nothing but the next prompt.

### 2.2 How a read works while unlocked

1. You run `multipass get github.com`. `open` connects to the socket for this store, checks the directory and the peer (§ 2.5), and sends `read`.
2. The agent asks for approval (§ 2.8), and macOS shows its Touch ID sheet: "multipass is trying to read your multipass store." When you cancel, or leave the sheet for 60 seconds, it replies `denied` and exits. When Touch ID and the watch are both unavailable at that moment, such as with the lid closed and no watch in reach, it replies `unavailable` and stays unlocked.
3. When you approve, the agent reads the store file and decrypts it with the vault key. When the vault key no longer opens it, because `rekey` ran here or on another machine, it replies `stale` and exits. Otherwise it replies with the store text.
4. `open` parses the text with `Store::from_text`, and the command goes on as today. On `denied`, the command fails with `the request was not approved`, and the next command asks for the passphrase. On `stale` or `unavailable`, or when no agent answers, `open` asks for the passphrase and a session starts as § 2.1 describes.

A store saved on another machine still opens, because both machines share the vault key through the synced key file.

### 2.3 How a change works while unlocked

1. You run `multipass add x`. `open_to_save` connects and sends `edit`.
2. The agent asks for approval with the reason `change your multipass store`, so a change sheet when you only ran `get` is a sign that something else asked. On approval it reads and decrypts the store, remembers the file's bytes, and replies with the store text. The connection stays open while the command asks for the secret, for up to 5 minutes.
3. The command makes its change and sends `save` with the new store text.
4. The agent checks that the store file still holds the bytes it read, encrypts the new text with the vault key at the vault-key plan's work factor, and writes it through `Store::save`'s temporary file and rename. It replies `saved`, or `changed` when another command saved in between, and the command then fails with `the store changed while you were editing; run the command again`.
5. When no agent answers, the command asks for the passphrase, opens the store, saves with the vault key it got from the key file, and starts a session as § 2.1 describes.

`passwd` and `rekey` always ask for the passphrase, because they rewrite the key file, which the passphrase encrypts. `passwd` keeps the vault key, so the running agent keeps working. `rekey` replaces it, so it sends `lock` to the old agent and starts a fresh one with the new key. `init` asks for a new passphrase and starts a session.

### 2.4 Commands, prompts, and settings

| Name | What it does |
| --- | --- |
| `multipass status` | Prints `unlocked until Dec 10 14:32`, or `locked`, followed by the reason from the end note when there is one, such as `locked: you declined a request at 13:05`. It asks for nothing. |
| `multipass lock` | Sends `lock` to the store's agent, and prints `Locked`, or `Not unlocked` when no agent answered. |
| The end note | When an agent ends, it writes `<hash>.ended` beside its socket, holding the reason and the time, such as `declined 1764160000`. The note holds no secret. The prompt and `status` read it, and a starting agent removes it. |
| The prompt | `Passphrase: ` when there is no end note and no socket, and otherwise `Passphrase (<reason>): `: `14 days passed`, `you declined a request`, `the vault key changed`, `locked by multipass lock`, or `the session ended` when a socket is left with no agent behind it, as after a restart. |
| `MULTIPASS_NO_AGENT=1` | `open` never asks an agent and no command starts one, so every command prompts as today. |
| `SSH_CONNECTION` | When it is set, `open` skips the agent and no command starts one. Nobody at the far end of SSH can touch the Mac's sensor, so asking would only leave a sheet on the Mac's screen until it times out and ends the session. |

Neither environment variable carries a secret, so the rule against secrets in the environment does not apply to them.

### 2.5 The socket and who may connect

| Part | Value |
| --- | --- |
| Directory | `~/.multipass/agent/`, created with mode 0700 by the existing `create_private_dir`. It stays under `$HOME` even when `MULTIPASS_STORE` points into a synced folder, so the socket never syncs. |
| Socket | `<hash>.sock`, where `<hash>` is the first 16 hex digits of the SHA-256 of the canonical store path. Each store gets its own agent, so `--store` keeps working. The path is public, so hashing it is not cryptography on a secret. |
| Directory check | Before every connect and bind, the client and the agent check that the directory belongs to the current user and has mode 0700, using `std::os::unix::fs::MetadataExt`. Otherwise they refuse to use it and name the directory. |
| Peer check | The agent calls `getpeereid` on each accepted connection and closes any whose user ID differs from its own. The client checks the agent's user ID the same way, and also that the agent runs the same executable as the client, from `LOCAL_PEERPID` and `proc_pidpath`, before it sends anything. This is the first gate, and the touch in § 2.8 is the second. |
| Platforms | macOS only, because Touch ID approval is macOS's and CI runs only there. On other systems no agent starts, and every command prompts as today. |

The agent handles each connection on its own thread, so an open `edit` does not hold up a `get`. It shows one Touch ID sheet at a time, and gives a client 2 seconds to send each request, so a client that stalls cannot hold it.

### 2.6 Messages

Every message is one line of ASCII, sometimes followed by a counted run of bytes. No reply names an entry or quotes the store outside the `read` and `edit` replies, and the agent writes no log.

| Message | Path | Reply |
| --- | --- | --- |
| `start <deadline-unix> <n>\n`, then the `n` bytes of the vault key's text | The agent's stdin, from the process that started it | `ready\n` on stdout, or exit with status 1 |
| `read\n` | Socket | `ok <n>\n` then `n` bytes of store text, or `denied\n`, `unavailable\n`, or `stale\n` |
| `edit\n` | Socket | The same as `read`, and on `ok` the connection waits for `save` |
| `save <n>\n`, then `n` bytes of store text | Socket, after `edit` on the same connection | `saved\n` or `changed\n` |
| `status\n` | Socket | `unlocked <deadline-unix>\n` |
| `lock\n` | Socket | `ok\n`, then the agent writes its end note, removes its socket, and exits |

The agent never sends the vault key. No message carries the passphrase. `status` and `lock` need no approval: the first reveals only that an agent runs, and the second can only end it.

### 2.7 What session unlock exposes

An agent trades a passphrase per command for a touch per command, and holds the vault key in memory between them, for up to 14 days. The touch keeps what the prompt guaranteed: no program can read or change the store without a person at the Mac. What it loses is the knowledge factor. A person at your Mac, once past its own lock screen, can use the store with an enrolled finger or your watch, without knowing the passphrase, until the session ends. Because sessions start on their own, everyone who uses multipass on a Mac with Touch ID or a watch has such a session after each prompt, unless they set `MULTIPASS_NO_AGENT=1`.

| Who | Without an agent | With an unlocked agent |
| --- | --- | --- |
| Another user on the Mac | Cannot read the store | Cannot connect: the directory check and the peer check refuse them |
| An AI coding agent running commands as you | Cannot answer the `/dev/tty` prompt without the passphrase, even through a fake terminal | Each `multipass get` or `add` it runs puts a Touch ID sheet on your screen. Nothing it can do presses the sensor or the watch, and declining ends the session. It cannot start a session either, because starting one takes the passphrase. |
| Malware running as you, reading | Must trojan the binary and wait for a prompt | The same as an AI agent, with one opening: it can send its `read` just before one of your own commands, so your touch approves its request. Your own command then asks a second time, which is the sign. Declining that second sheet ends the session. |
| Malware running as you, writing | Cannot write a valid store without the passphrase | Needs a touch, with the same opening as reading. A stolen change can delete or replace entries silently, and only a backup restores them. The sheet says `change your multipass store`, so a change sheet when you ran only `get` is the sign. |
| Malware running as you, posing as the agent | Nothing to pose as | Must run the `multipass` binary to pass the client's executable check, and that binary only ever holds a key the command handed it. A program that can replace the binary can already capture the passphrase at the next prompt, without an agent. |
| A person at your Mac, past its lock screen | Needs the passphrase | Needs an enrolled finger or your watch, for up to 14 days |
| Root, or a memory attack | Can read the passphrase from a command's memory while it runs | The agent denies debugger attachment with `ptrace(PT_DENY_ATTACH)`, so a debugger fails, but root can still copy the vault key from memory without any touch. The vault key opens every copy of the store written under it, here, in sync, and in backups, until you run `multipass rekey`. It does not reveal the passphrase. |
| A crash report or core dump | Could hold the passphrase from a running command | The agent sets `RLIMIT_CORE` to 0, so it leaves no core file |

The README says this plainly, names `MULTIPASS_NO_AGENT=1` for anyone who wants a prompt every time, shows `multipass lock` for ending a session early, and says to run `multipass rekey` if the Mac may have been compromised.

### 2.8 Approval with Touch ID or an Apple Watch

| Part | Value |
| --- | --- |
| Framework | LocalAuthentication's `LAContext`, called from `src/touch_id.rs` through the Objective-C runtime, as `src/clipboard.rs` calls AppKit. It needs no Keychain item and no entitlement, so it works from an unsigned command-line program. |
| Policy | `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch`: a finger on Touch ID, or a double press on a paired Apple Watch. Not `LAPolicyDeviceOwnerAuthentication`, which falls back to the login password, because a program that knows or captures that password could type it. |
| At start | `canEvaluatePolicy` must succeed, or the agent exits and no session starts (§ 2.1 step 4). |
| Each `read` or `edit` | A fresh `LAContext` and one `evaluatePolicy` call, with the reason `read your multipass store` or `change your multipass store`. One approval covers one request, with no grace period. |
| Approved | The agent goes on with the request. |
| Cancelled, failed, or 60 seconds with no answer | The agent replies `denied`, calls `invalidate` on the context, writes its end note, and exits. A request you did not expect means something else asked, so the agent stops serving anyone. |
| Unavailable at that moment | `LAErrorBiometryNotAvailable`, `LAErrorBiometryLockout`, or no watch in reach: the agent replies `unavailable` and stays unlocked, and the command asks for the passphrase. |

The reply arrives in an Objective-C block on a queue LocalAuthentication owns. `src/objc.rs` builds that block by hand, a global block with no captured variables, and the block hands the result to the waiting agent thread through a `std::sync::mpsc` channel.

### 2.9 When a session ends

Ending means the agent writes its end note, removes its socket, and exits, so the vault key leaves memory with the process. It costs you one passphrase prompt on the next command, which starts a fresh session.

| Trigger | How it happens |
| --- | --- |
| 14 days | A thread sleeps until 14 days after the session started, by the wall clock, so time asleep counts. A save while unlocked keeps the session's deadline; only a passphrase prompt starts a new 14 days. |
| A restart or logout | The agent is a process, so it ends with the login session. Its socket file stays behind, which is how the next prompt knows to say `the session ended`. |
| A declined request | § 2.8. |
| `multipass lock` | § 2.4. |
| A changed vault key | The vault key no longer opens the store (§ 2.2 step 3), after `rekey` here or on another machine. |

Sleep, the screen lock, and time without use do not end a session. Every request already needs a touch, so they would only add passphrase prompts.

### 2.10 Neighbors: passkeys and the clipboard

- **The passkeys Keychain item.** The passkeys plan's extension keeps the passphrase in a Keychain item that only its own access group can read. The CLI is not signed into that group, so the agent cannot use the item, and the extension cannot use the agent. They stay independent, though both now use Face ID or Touch ID. After the vault key ships, the extension could keep the vault key in its item instead of the passphrase; the passkeys plan decides that. The passkeys plan's § 2.3 says the CLI "still asks for the passphrase every time"; this project changes that sentence to point here.
- **`--clip`.** `get --clip` and `otp --clip` are a separate feature, in pull request #9. They copy the value through AppKit's `NSPasteboard`, marked current-host-only and concealed. A detached `multipass __clear-clipboard <count>` process clears the clipboard 30 seconds later, and only if the pasteboard's change count still equals `<count>`. `--clip` reads the value through `open`, so it asks for the same touch as `get`. The clearing process never touches the store, so it does not depend on the agent.

### 2.11 Changes by file

This table assumes the vault-key plan has shipped, and that pull request #9, which adds `--clip` and `src/clipboard.rs`, merged first.

| File | Change |
| --- | --- |
| `src/store.rs` | No new code. The agent decrypts with `Store::decrypt`, given the vault key's text, and writes a changed store with `Store::save`. |
| `src/agent.rs` | New. The agent half: reads the start message from stdin, binds the socket, answers `read`, `edit` and `save`, `status`, and `lock` on a thread per connection, ends the session as § 2.9 says, and writes the end note. It asks for approval through an `Approver` trait, which `touch_id::TouchId` implements and tests replace with a fake. The client half: `read`, `edit`, `status`, `lock`, `end_note`, and `start`, which spawns an agent and writes the start message. The socket path, the end note's path, and the directory check live here, shared by both halves. |
| `src/touch_id.rs` | New `unsafe` module. Links `LocalAuthentication.framework`, and wraps `canEvaluatePolicy:error:`, `evaluatePolicy:localizedReason:reply:`, and `invalidate` in a safe `TouchId::available()` and `TouchId::approve(reason, timeout) -> Approval`, where `Approval` is `Approved`, `Denied`, or `Unavailable`. |
| `src/objc.rs` | New `unsafe` module. The typed `objc_msgSend`, class, selector, and `NSString` helpers move here from `src/clipboard.rs`, so the clipboard and Touch ID share one copy, and it adds the global block that carries `evaluatePolicy`'s reply. |
| `src/clipboard.rs` | Calls the helpers in `src/objc.rs` instead of defining its own. Its module comment stops calling it the program's only `unsafe` code. |
| `src/sys.rs` | New `unsafe` module, built like `src/clipboard.rs`: `unsafe extern "C"` declarations for `getuid`, `getpeereid`, `getsockopt(LOCAL_PEERPID)`, `proc_pidpath`, `setsid`, `ptrace(PT_DENY_ATTACH)`, and `setrlimit(RLIMIT_CORE)` behind safe wrappers, under `#[cfg(target_os = "macos")]`. The standard library offers no stable call for any of them at `rust-version = "1.85"`. |
| `src/main.rs` | Adds `status`, `lock`, and the hidden `__agent` command, named like `__clear-clipboard`. `open` asks the agent with `read` unless § 2.4's variables say not to, fails on `denied`, and otherwise prompts with the reason from the end note, then starts an agent once the command succeeds. `add`, `rm`, `otp --set`, and `otp --clear` call a new `open_to_save`, which asks with `edit` and saves with `save`, and falls back the same way. `passwd` and `rekey` always prompt, and `rekey` replaces the agent. Updates `USAGE`. |
| `README.md` | Documents sessions: the touch for each read and change, when a session ends, `status`, `lock`, `MULTIPASS_NO_AGENT`, and § 2.7's trade in a few sentences, with `rekey` as the remedy for a suspected compromise. Changes "Every command asks for the passphrase" and removes "Session unlock" from "Not built yet". |
| `AGENTS.md` | Changes the rule "Apple's system frameworks count like the standard library", which says `src/clipboard.rs` "holds the program's only `unsafe` code", so it names `src/objc.rs`, `src/clipboard.rs`, `src/touch_id.rs`, and `src/sys.rs` as the modules that hold `unsafe` code, each behind a safe interface, with a comment on each call saying what it requires of its arguments. Adds the agent's rules: the vault key reaches an agent only through the stdin of a child the CLI started; the agent answers `read` and `edit` only after an approval for that one request; it never sends the vault key. |
| `docs/projects/passkeys/readme.md` | § 2.3's sentence about the CLI changes as § 2.10 says. |

## 3. Why this design

- **A vault key between the passphrase and the store.** The age specification says a file key "MUST NOT be reused across multiple files", and that "A new salt MUST be generated for each stanza and each file", so every save needs scrypt and whatever secret the store is encrypted under. Today that secret is the passphrase, so an agent that saves would have to hold it. With the vault key, the agent holds a random key that never leaves multipass, and the passphrase sits in memory only during a prompt. This was the user's design, and it removes the choice this plan used to offer between saves that prompt and an agent that holds the passphrase.
- **The vault key as its own plan.** It changes the on-disk layout, recovery, and sync advice, and it is useful before any agent exists, so it ships and is reviewed first. Nesting it under this plan records that session unlock depends on it, and keeps each plan small enough for one reviewer.
- **A touch for every request.** The worry this design answers is a program, an AI coding agent above all, that runs `multipass` as you while the store is unlocked. Every way to tell such a program from you in software fails, because it runs as you, can start from your terminal, and can fake a terminal or click a dialog. A finger on Touch ID or a press on the watch is physical, so it is the one check no program can pass. Asking on every request, with no grace period, means a program can never ride on an approval you gave a moment earlier.
- **Changes need a touch too, and say so.** Typing the passphrase for every `add` was the cost the user rejected. A touch keeps changes behind a person, and the distinct reason on the sheet makes a stolen change easier to notice than a stolen read.
- **Sessions start on their own and last 14 days.** An explicit `unlock` command would make you keep track of whether the last session has ended, and people are bad at keeping track of time. A command that already had to prompt starts a session at no extra cost, and the prompt's reason tells you why it asked again. The case for short sessions, and for an explicit `unlock`, was that an unlocked store lets programs read it. The touch for every request takes that away, so what a long session still costs is the vault key's time in memory, where only root or a memory attack can reach it. 1Password's Touch ID unlock makes a similar trade: it asks for the account password after a restart, and otherwise on a schedule you set.
- **No locking on sleep, the screen lock, or idle time.** Each would add passphrase prompts without stopping anything the touch does not already stop. A person at the Mac must first get past its own lock screen.
- **Declining ends the session.** A sheet you did not expect is evidence that something else is asking. Ending the session stops a program from asking again and again until a reflexive touch approves it, and the cost is typing the passphrase once after a mistaken cancel.
- **Unavailable falls back to the passphrase.** With the lid closed and no watch, the passphrase prompt still proves a person is there, so it is a safe fallback. A cancelled sheet does not fall back, because that would let a program turn your "no" into a second chance.
- **SSH skips the agent.** `SSH_CONNECTION` comes from the SSH server and a client could ignore it, so the check is a courtesy, not a gate: a client that ignores it gets a sheet on the Mac like any other. It keeps a remote command from leaving a sheet nobody can answer, which would time out and end the session at the desk.
- **The agent reads the file on every request.** It never caches the decrypted store, so plaintext sits in its memory only while it answers, and a store saved on another machine is served as it now is.
- **The key crosses a pipe, never the socket.** Any process running as you can bind the socket path while no agent runs. If a command sent the key over the socket, such a process could pose as the agent and collect it. A pipe to a child the command started itself offers no such opening.
- **Ending means exiting.** One rule covers every trigger, and no locked process stays behind. The end note outlives the process only to explain the next prompt.
- **Reuse.** The agent decrypts through `Store::decrypt` and saves through `Store::save`, so it reads and writes the store exactly as a prompted command does. The Objective-C helpers move out of `src/clipboard.rs` into `src/objc.rs`, so Touch ID does not repeat them. The directory comes from `create_private_dir`, and the socket's hash from `crypto::sha256`.
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
| `multipass get github.com` again, and touch the sensor | No passphrase prompt. The sheet says "read your multipass store", then the secret prints. |
| `multipass get github.com` a third time, right away | The sheet appears again: one touch covers one request |
| `multipass add x`, touch the sensor, and type the secret | One sheet, saying "change your multipass store", and no passphrase prompt. `multipass get x` and a touch then print the secret. |
| `multipass get github.com`, and cancel the sheet | `get` fails with `the request was not approved`, and the agent has exited. The next `get` asks `Passphrase (you declined a request): `. |
| `multipass get github.com`, and leave the sheet for 60 seconds | The same as cancelling |
| While unlocked, run `multipass get github.com` from a script started with no terminal | The Touch ID sheet appears, and nothing prints until someone touches the sensor |
| Over SSH, `multipass get github.com` while an agent runs at the desk | Asks for the passphrase, shows no sheet on the Mac, and the desk's agent keeps running |
| `MULTIPASS_NO_AGENT=1 multipass get github.com` twice | Both ask for the passphrase, and no agent starts |
| With the lid closed, an external display, and no Apple Watch, `multipass get github.com` while unlocked | `get` asks for the passphrase, and the agent stays unlocked |
| `pmset sleepnow` while unlocked, wake the Mac, then `multipass get github.com` | Only the sheet, no passphrase prompt |
| Restart the Mac, then `multipass list` | Asks `Passphrase (the session ended): ` |
| Two `multipass add` commands at once, each touched | One saves. The other fails with `the store changed while you were editing; run the command again`, and the store holds the first change. |
| `multipass rekey` while unlocked, then `multipass get github.com` | `rekey` asks for the passphrase. `get` asks only for a touch, so the fresh agent holds the new key. |
| `multipass rekey` on another machine, let the key file and store sync, then `multipass get github.com` here and touch the sensor | Asks `Passphrase (the vault key changed): ` |
| `multipass status` while unlocked, then `multipass lock`, `multipass lock`, `multipass status` | `unlocked until …` about 14 days out, then `Locked`, then `Not unlocked`, then `locked: locked by multipass lock …` |
| `chmod 755 ~/.multipass/agent`, then `multipass list` | Refuses to use the agent, names the directory, and asks for the passphrase |
| `lldb -p <agent pid>` | Attaching fails |
| `ps -o args= -p <agent pid>` | Shows `multipass --store <path> __agent` and nothing secret |

Tests that must fail before the change and pass after it:

- **The start message** round-trips through its writer and reader, and the reader rejects a short key, a missing count, and trailing bytes. Catches a key that arrives truncated.
- **The approval gate**, with a fake `Approver` that counts its calls and records each reason. Two `read`s call it twice, and `edit` asks with `change your multipass store`. `Denied` sends `denied`, sends no store bytes, writes the end note, and the agent exits. `Unavailable` sends `unavailable` and the agent keeps serving. Catches an agent that sends text before approval, a grace period that slips in, a change approved under the read reason, and a cancel that does not end the session.
- **`edit` and `save`.** With an approving fake, `edit` returns the store text and `save` writes the new text, which `Store::open` then reads with the passphrase. A store rewritten between `edit` and `save` gets `changed` and keeps the rewrite. A `save` with no `edit` before it on the connection is refused. Catches a lost update and a save that skips approval.
- **The deadline**: an agent given a deadline in the past ends at once with `14 days passed`, and a save keeps the deadline it started with. Catches a session that outlives its 14 days, or one that a busy week keeps alive forever.
- **The end note and the prompt.** Each reason the agent writes turns into its prompt text. A socket with no agent behind it gives `the session ended`, and a missing note, or one with an unknown reason, gives `Passphrase: `. Catches a prompt that blames the wrong cause.
- **The agent switches in `open`**, as a pure function of `MULTIPASS_NO_AGENT` and `SSH_CONNECTION`. Catches an opt-out that still starts an agent.
- **The directory check** refuses a directory with mode 0755 and accepts 0700, in a temporary directory. Catches a socket other users could reach.
- **An agent end to end**, in a temporary directory with an approving fake: start it with a vault key, and `read` returns the store text, `status` reports the deadline, a store re-encrypted under another key makes `read` return `stale`, and `lock` removes the socket and leaves an end note. Catches a message format the two halves disagree on.

`src/touch_id.rs` needs a finger, so no automated test covers it. The sheet rows of the table above check it by hand.

## 5. Cost

An approved request costs one touch, about a second of your time, plus one socket round trip, one file read, and scrypt at the vault-key plan's work factor 10, a few milliseconds in all. A change adds one encryption at the same work factor. Today's read costs typing the passphrase plus about 300 ms of scrypt, and a change costs that twice. A command that prompts still runs the 300 ms once, on the key file, and starting the agent after it adds a process start and the agent's `canEvaluatePolicy` call, well under the 2 seconds the command waits. The agent idles in a sleeping thread between requests and holds a 43-character key.

## 6. Open questions

Only § 6.5 is open, and it waits on a prototype. Questions 6.1 to 6.4 are decided, and § 2 is written for those decisions.

### 6.1 What the agent holds

Decided: a vault key, as the [vault-key plan](vault-key/readme.md) describes. The passphrase unlocks a random vault key kept in a key file beside the store, and the vault key encrypts the store. The agent holds only the vault key and serves both reads and changes, each with a touch, so the passphrase is in memory only during a prompt. The earlier choice, between an agent that holds only the store's file key, where every save prompts, and one that holds the passphrase, no longer arises.

### 6.2 When it locks

Decided: a session lasts at most 14 days, and a restart ends it, because the key is only in memory. There is no idle timeout and no locking on sleep or the screen lock, because the touch for every request is the guard. `multipass lock`, and declining or timing out an unexpected Touch ID sheet, end it too.

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
