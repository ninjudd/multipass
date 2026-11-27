---
status: ready
priority: now
---

# Vault key

The store becomes a package, a folder holding a key file and the store. The passphrase unlocks a random vault key in the key file, the vault key encrypts the store, and the vault key is replaced every 14 days and on every `passwd`.

## 1. Problem

Today the passphrase encrypts the store directly. `Store::save` runs scrypt at work factor 18 on the passphrase, about 300 ms, and the age format requires a fresh salt and file key for every file. So every save needs the passphrase itself, and `passwd` re-encrypts the whole store.

That blocks session unlock, which `docs/projects/session-unlock` plans next. Its agent must save while you are not typing, and an agent that saves under today's design must hold the passphrase, which opens every copy of the store ever written under it. A key between the passphrase and the store lets the agent hold that key instead. Replacing that key on a schedule bounds how long a copied key stays useful, and gives every Mac one shared deadline for its session. Commands in this project still ask for the passphrase every time; only the layout and the keys change.

## 2. Solution

A store becomes a package: a directory, `~/.multipass/store.multipass` by default, holding two ordinary age passphrase files. `key.age` is encrypted under your passphrase at work factor 18, as the store is today. It holds a random 256-bit vault key, written as base64 text, and the time the key was made. `store.age` is encrypted with that text as its passphrase, at work factor 10. A random 256-bit key needs no stretching, so scrypt stays there only because age's passphrase mode is what lets stock `age -d` open the file. Opening runs the slow scrypt once on `key.age`, then the fast one on `store.age`. Saving runs only the fast one, with a fresh salt and file key as the age format requires.

A vault key lasts 14 days. The first passphrase prompt after it expires, on whichever Mac comes first, rotates it: it makes a new vault key, re-encrypts `store.age`, and rewrites `key.age`, in an order a crash cannot break. `passwd` rotates too, so an old passphrase never leads to the current key, and `multipass rekey` rotates on demand. A store written by today's multipass keeps opening, and moves into a package at its first passphrase prompt. Stock `age -d` still recovers everything, in two steps.

### 2.1 The package

| Path | What it is | Encrypted under | Work factor | Plaintext |
| --- | --- | --- | --- | --- |
| `store.multipass/` | The package, named by `--store` or `MULTIPASS_STORE`, by default `~/.multipass/store.multipass`. A directory with mode 0700. | | | |
| `store.multipass/key.age` | The key file | Your passphrase | 18 (`age::DEFAULT_WORK_FACTOR`) | `multipass-key 1`, then one or two lines of `key <vault key> <created>` |
| `store.multipass/store.age` | The store, one file for every entry | The text of a vault key from `key.age` | 10 (new `age::VAULT_WORK_FACTOR`) | The store text, `multipass 2`, unchanged |

A vault key is 32 bytes from `crypto::random::fill`, encoded by `crypto::base64::encode` as 43 characters of unpadded base64. `<created>` is the Unix time it was made. The store's passphrase is those 43 characters as bytes, so multipass never decodes the key. `key.age` holds two `key` lines only while a rotation runs (§ 2.4).

```text
multipass-key 1
key mXHnHUSvp+wCWtqvVrFcsN82rLveCB+L/s0F/V5yi9E 1764160000
```

Finder shows a directory as one item only when an installed app declares its extension as a package type. Until the passkeys plan's Mac app declares `.multipass`, Finder shows `store.multipass` as an ordinary folder with two files in it. That costs nothing: iCloud Drive, Dropbox, git, and Time Machine already sync, copy, and back up a folder as a unit, and multipass never needs Finder's view. The README tells you to move or copy the whole folder, never one file out of it.

### 2.2 How a store opens

1. `open` asks for the passphrase and reads both files.
2. It decrypts `key.age` with the passphrase. A wrong passphrase fails here with `wrong passphrase, or the store is damaged`, as today.
3. It tries each `key` line, in order, as the passphrase of `store.age`. The first that opens it is the vault key. When the file held two lines, `open` finishes or undoes the interrupted rotation (§ 2.4).
4. When no line opens `store.age`, `open` tries every other `.age` file in the package as a key file, because sync services leave conflict copies there, such as `key 2.age`. When one works, it uses that key and warns, naming the conflict copies. When none does, it fails with `key.age does not open store.age; if they are still syncing, try again shortly`, and names any conflict copies it found. It never deletes them, because multipass does not merge.
5. When the vault key is 14 days old or older, `open` rotates it before the command runs (§ 2.4).

### 2.3 How a save works

`Store::save` takes the vault key instead of the passphrase, and encrypts the store with it at work factor 10, with a fresh salt and file key, through the existing temporary file and rename inside the package. It never touches `key.age`. A save no longer needs the passphrase, which is what lets session unlock's agent save while you are not typing.

### 2.4 Rotation

Rotation replaces the vault key. One function does it, `vault::rotate(package, store, passphrase)`, and four things call it.

| Caller | When | Passphrase for the new `key.age` |
| --- | --- | --- |
| `open` | The current key is 14 days old or older | The one you just typed |
| `passwd` | Every time | The new one |
| `multipass rekey` | When you ask, for a suspected leak | The one you just typed |
| `init` | Once, to make the first key | The new one |

Each rotation makes a new vault key and writes three times, each through a temporary file and a rename. `init` has no old key, so it writes only `store.age` and then step 3.

1. `key.age` with two lines, the old key then the new, under the old passphrase.
2. `store.age` under the new key.
3. `key.age` with only the new key, under the passphrase the table names.

A crash at any point leaves files that open with the old passphrase, or after step 3 with the new one. Before step 2 the old key opens the store, and after it the new key does. `open` (§ 2.2 step 3) tries both lines, and when it finds two, it rewrites `key.age` with only the line that opened the store, since it has the passphrase in hand. A rotation that stopped before step 2 is then undone, and the next expired prompt, or the next `passwd` or `rekey`, does it again. A `passwd` that stopped before step 3 leaves the old passphrase in force, and says so when you run it again.

#### 2.4.1 One deadline for every Mac

The creation time travels inside `key.age`, so every Mac that syncs the package sees the same expiry.

1. Your key expires on Monday. On Tuesday you type the passphrase on your laptop. The laptop rotates, and the new `key.age` and `store.age` sync.
2. On Wednesday you type the passphrase on your desktop. It reads the new `key.age`, finds a key a day old, and does not rotate.
3. A Mac where nobody types the passphrase for months rotates at its next prompt only if the key it reads then is expired. If another Mac rotated in the meantime and sync has delivered the files, the key is fresh, and it does not.
4. A Mac that comes back online and prompts before sync delivers the newer files rotates from the stale ones. The two Macs then hold different keys, and the sync service keeps one version of each file and a conflict copy of the other. § 2.2 step 4 opens the store with whichever key matches and names the conflict copies. If `store.age` has a conflict copy too, the README's recovery steps open it with the other key, as they would any conflicting edit today.

So each Mac asks for the passphrase about once per 14 days, and usually only the first to ask rotates. Sync both files of the package, and edit on one machine at a time, as today.

### 2.5 Moving a store into a package

A store from before this project is a single `store.age` file encrypted under the passphrase. When `--store` or `MULTIPASS_STORE` names such a file, `open` asks for the passphrase, decrypts it, and moves it into a package beside it, named for it with `.multipass` in place of `.age`:

1. It writes `key.age` and `store.age` into a new directory, `store.multipass.tmp`, with a fresh vault key.
2. It renames that directory to `store.multipass`. The rename is atomic, so the package appears whole or not at all.
3. It removes the old `store.age`, and prints `Moved <old file> into <package>` to stderr.

The default path follows the same steps: with no `--store` and no `MULTIPASS_STORE`, multipass uses `~/.multipass/store.multipass`, and when that does not exist but `~/.multipass/store.age` does, it moves that file. When `--store` or `MULTIPASS_STORE` still names the old file after the move, multipass opens the package beside it and prints `note: <old file> moved to <package>; update MULTIPASS_STORE or --store`. A crash before step 2 leaves a `.tmp` directory, which the next attempt removes and rebuilds. A crash before step 3 leaves both, and the package wins, with the old file removed at the next open.

After the move, an older multipass cannot open the store, because it looks for a single file. The README says so.

### 2.6 Recovering the store with stock age

The README's recovery section becomes two steps:

```sh
age -d ~/.multipass/store.multipass/key.age     # copy the text after "key ", up to the space
age -d ~/.multipass/store.multipass/store.age   # paste that text at age's passphrase prompt
```

When `key.age` shows two `key` lines, an interrupted rotation left them, and one of the two opens the store.

### 2.7 What the vault key exposes

| Who | Today | With a vault key |
| --- | --- | --- |
| Someone with a copy of the package, guessing offline | Runs scrypt at work factor 18 for every guess at the passphrase | The same, on `key.age`. The store's key is random and 256 bits, so guessing it is hopeless despite its low work factor. |
| Someone who learns the passphrase and has the files | Reads the store | The same, through `key.age` |
| Someone who copies a vault key, for example from session unlock's agent | Not possible | Reads every copy of the store written under that key, here, in sync, and in backups. The next rotation retires it, so it opens no store written after that, at most 14 days later, or at once after `rekey`. The key does not reveal the passphrase. |
| Someone with an old passphrase and an old copy of `key.age`, such as from a git history or a backup | After `passwd`, reads only copies of the store from before the change | The same. `passwd` rotates the vault key, so the old `key.age` yields a retired key that opens only copies of `store.age` from before the change. |
| A future quantum computer | Nothing to attack: passphrase mode is symmetric | The same. Both files use only scrypt and ChaCha20-Poly1305. |
| Someone who sees the synced files without decrypting them | Sees one file and when it changes | Sees two files, when they change, and so roughly when a rotation happened. The entry names, count, and sizes stay inside the one `store.age`. |

### 2.8 Changes by file

| File | Change |
| --- | --- |
| `src/age.rs` | Adds `VAULT_WORK_FACTOR`, 10. `encrypt` and `decrypt` are unchanged, and `decrypt` already accepts work factors 1 to 22. |
| `src/crypto/base64.rs` | `encode` stops indexing `ALPHABET` with the data, and maps each 6-bit value to its character with masked arithmetic, because it now encodes the vault key. The RFC 4648 tests stay and must still pass. `decode` keeps its `match`, because nothing secret passes through it here; the passkeys plan changes it too. |
| `src/vault.rs` | New. `VaultKey`, which holds the 43-character text and its creation time and never prints the text in `Debug`; `VaultKey::generate`; reading and writing `key.age`'s text; `rotate`, with the steps in § 2.4; the conflict-copy search in § 2.2 step 4; and the move into a package in § 2.5. The key file's parsing treats the key as text, as `src/store.rs` treats secrets. |
| `src/store.rs` | `Store::save(package, &VaultKey)` encrypts at `VAULT_WORK_FACTOR` into the package. New `Store::open(package, passphrase) -> (Store, VaultKey)` follows § 2.2, including rotation on expiry. `Store::load` goes, and its one caller moves to `Store::open`. `save` keeps writing a temporary file and renaming it, now inside the package. |
| `src/main.rs` | The default store path becomes `~/.multipass/store.multipass`, and `--store` and `MULTIPASS_STORE` name a package, with the old-file handling in § 2.5. `open` returns the vault key in place of the passphrase, and every save passes it. `init` and `passwd` call `rotate`. Adds `rekey` to the commands and `USAGE`. |
| `README.md` | The recovery section shows § 2.6. "Sync between machines" says to sync and move the whole package, and that each Mac asks for the passphrase about once per 14 days. "Why it is built this way" says the passphrase unlocks a random vault key that rotates every 14 days, and the store is still only passphrase-mode age. Documents the move into a package, `rekey`, and that older builds cannot open a package. |
| `AGENTS.md` | "Keep the store readable by stock age" changes from one `age -d` to the two steps in § 2.6, and the hand check runs both. Adds `src/vault.rs` to the places that keep secrets as text. "Write the store atomically" covers `key.age`, the package's temporary directory, and the rotation order. |

## 3. Why this design

- **Two stock age files, not a new format.** Wrapping the vault key in its own age file keeps every byte on disk readable by `age -d`, which AGENTS.md requires, and keeps multipass in passphrase mode with no public-key step. A custom wrapper inside one file would need its own parser and would break stock-age recovery.
- **A package rather than two loose files.** The two files must travel together: a store without its key file opens for no one. A directory keeps them together through sync, backups, and moves, and gives conflict copies a place to land where multipass can find them. Naming it with `.multipass` lets the Mac app later make Finder show it as one item.
- **One `store.age`, not a file per entry.** Files per entry would show anyone who sees the synced folder how many entries you have, how long each secret is, and when you change each one. A save that touches two entries could not be atomic, and recovery would mean decrypting every file by hand. One file hides all of that, as the store does today.
- **The vault key as text.** age's passphrase mode takes a passphrase, so the store's passphrase is the key's base64 text. Using the text as it is means multipass never decodes the key, and `key.age` shows exactly what to paste into `age -d`.
- **Work factor 10 for the store.** scrypt slows down guessing a weak passphrase. Nobody can guess a random 256-bit key, so stretching it buys nothing, and work factor 10, about a megabyte and a millisecond, keeps saves instant. The tests already use 10, and `age::decrypt` accepts it. The reference `age` crate sets no lower bound either.
- **A 14-day key.** A key copied from memory should not stay useful forever, and session unlock needs a deadline every Mac agrees on. Putting the creation time in `key.age` does both: the key's age is the session's age on every Mac, and the rotation that ends it also retires the key. Rotating needs the passphrase, so it happens at the prompt that expiry causes anyway.
- **`passwd` rotates.** Changing the passphrase because someone may know it must also lock them out of the current store, and with a vault key that means a new key. The cost is that other Macs' sessions end, which is rare and costs one prompt each.
- **Two `key` lines during rotation.** Two files cannot be renamed together, so `key.age` holds both keys while the store changes over. Every crash point then leaves a key that opens the store, without a journal or a lock file. The passphrase changes only in the last step, so a `passwd` cut short leaves the old one working.
- **The move happens at the first prompt.** The passphrase is in hand only at a prompt, and session unlock's agent needs a vault key from its first session. Building the package in a temporary directory and renaming it makes the move all or nothing.
- **Its own plan, before session unlock.** It changes the on-disk layout, recovery, and sync advice, and it is worth having alone, for the 14-day key, `rekey`, and a `passwd` that locks out an old passphrase. Session unlock builds on it.
- **Reuse.** Both files go through `age::encrypt` and `age::decrypt`, and every write goes through the temporary-file-and-rename route in `Store::save`, which `src/vault.rs` calls for `key.age` rather than repeating it. `init`, `passwd`, `rekey`, and expiry share one `rotate`.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass init`, then `ls -la ~/.multipass/store.multipass` | The directory has mode 0700 and holds `key.age` and `store.age`, both mode 0600 |
| `age -d` on `key.age` with the passphrase, then `age -d` on `store.age` with the key text | The first prints `multipass-key 1` and one `key` line with a creation time, the second prints `multipass 2` and the entries. Run with both the reference Go `age` and the `age` crate. |
| `multipass add x`, then `age -d` on `store.age` with the vault key | The store holds `x`, and `key.age`'s bytes did not change |
| `multipass passwd`, then `multipass list` with the new passphrase | Lists the entries. `key.age` holds a different key line, and the old key no longer opens `store.age`. |
| `multipass rekey`, then `multipass list` | Lists the entries, and the key line has changed |
| Point `MULTIPASS_STORE` at a single-file store written by today's multipass, then `multipass list` | Asks for the passphrase, lists the entries, prints `Moved …`, and a package sits where the file was. A second `multipass list` prints the `note: … update MULTIPASS_STORE` line. |
| Sync a package between two machines, run `multipass rekey` on one, let both files sync, then `multipass list` on the other | Opens with the new key and leaves `key.age` unchanged. The 14-day expiry itself is covered by the tests below, since nobody waits two weeks by hand. |
| `multipass list` on a package whose two files do not match | Fails with `key.age does not open store.age; if they are still syncing, try again shortly` |
| Put a conflict copy of `key.age`, holding the matching key, beside a mismatched `key.age`, then `multipass list` | Lists the entries and warns, naming the conflict copy |

Tests that must fail before the change and pass after it:

- **Expiry rotates once.** A key made 14 days ago rotates at `open`, and a key made 13 days ago does not. After the rotation, `open` with the same passphrase finds a fresh key and does not rotate again. Catches a rotation that never happens, and one that happens on every prompt.
- **Rotation survives a crash at each step.** A test runs the steps in § 2.4 one at a time in a temporary directory, for `rekey` and for `passwd`, stops after each, and opens the store. Every stop opens with the old passphrase, or after step 3 with the new one, and the entries match. Catches a write order that leaves the two files disagreeing, and a `passwd` cut short that strands you between passphrases.
- **Opening tries each key line**, and afterwards `key.age` holds only the line that opened the store. Catches a rotation that crashed between steps and left the store unopenable.
- **Conflict copies.** A package whose `key.age` does not match, with a `key 2.age` that does, opens and names `key 2.age`, and the copy is still there afterwards. Catches a sync conflict that locks you out, and a cleanup that deletes a version.
- **`passwd` retires the old key.** After `passwd`, the old passphrase on a saved copy of the old `key.age` yields a key that does not open the new `store.age`. Catches a `passwd` that keeps the vault key.
- **The move into a package**, and a move cut short. A single-file store opens and leaves a package and no old file. A leftover `.tmp` directory is rebuilt, and an old file left beside a finished package is removed. Catches a crash in the move that loses the store.
- **Path handling**: no setting gives `~/.multipass/store.multipass`; a `--store` naming an old `.age` file that has moved opens the `.multipass` beside it; a `--store` naming any directory opens it as a package. Catches a store that lands somewhere sync does not carry.
- **`base64::encode` still matches RFC 4648** after the masked rewrite, for every byte value. Catches a masked mapping that is off at a range boundary, such as 25 to 26 or 61 to 62.
- **`VaultKey`'s `Debug` output** holds no key text. Catches a key that reaches an error message.

## 5. Cost

Opening runs scrypt at work factor 18 once, on `key.age`, the same 300 ms as today, plus a millisecond at work factor 10 for the store. A save drops from 300 ms to about a millisecond. A rotation adds two writes of `key.age` at work factor 18, about 600 ms, once every 14 days, and on `passwd` and `rekey`. The move into a package happens once per store.

## 6. Open questions

None. Every decision here is the user's: the package, one `store.age` inside it, the low work factor for the store, the 14-day key, rotation on `passwd`, and `rekey`.
