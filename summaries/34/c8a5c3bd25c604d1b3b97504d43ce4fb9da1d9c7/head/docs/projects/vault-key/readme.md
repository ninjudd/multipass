---
status: completed
priority: now
---

# Vault key

The store becomes a package of files that are never modified once written. The passphrase unlocks a random vault key, the vault key encrypts the store, every save adds a new file, and the vault key is replaced at least every 21 days and on every `passwd`.

This project depends on the [mergeable store](../store-merge/readme.md), which ships first and supplies store format 3 and `Store::merge`.

## 1. Problem

Today the passphrase encrypts the store directly, in one file that every save replaces. That causes three problems.

- **Every save needs the passphrase.** `Store::save` runs scrypt at work factor 18, about 300 ms, and the age format requires a fresh salt and file key for every file. So session unlock, which comes next, would need an agent that holds the passphrase, which opens every copy of the store ever written under it.
- **Sync can destroy changes.** When two Macs save before sync catches up, the sync service must reconcile two writes to the same file, and one is lost. So the README says to edit on one machine at a time.
- **Changing keys makes that worse.** A design that replaced a key on a schedule would rewrite the key file and the store together. If another Mac saved under the old key before the new files arrived, the sync service could leave a store beside a key file that does not open it, and the store would be lost for good.

## 2. Solution

A store becomes a package: a directory, `~/.multipass/store.multipass` by default, of ordinary age passphrase files that multipass writes once and never modifies. A key file, `key.<generation>.age`, is encrypted under your passphrase at work factor 18 and holds a random 256-bit vault key, the time it was made, and the keys it replaced in the last 90 days. A store file, `store.<generation>.<random>.age`, is encrypted with the vault key's text at work factor 10, and holds a whole store in format 3. Every save writes a new store file holding the merged store plus the change, then deletes the files it read. Opening decrypts every store file it has a key for and merges them, entry by entry, with `Store::merge`. A file another Mac writes at the same moment is never touched, survives, and is merged next time, so no sync service can lose a change, and edits on two Macs to different entries both survive.

A vault key lives 21 days. Any passphrase prompt rotates it when it is 14 or more days old: it writes a new key file and a new store file under the new key, then deletes the old ones. `passwd` always rotates, and `multipass rekey` rotates on demand. So after you type the passphrase on a Mac, its key has at least 7 days left, and without restarts you type it about every 21 days. A store from today's multipass moves into a package at its first prompt, and stock `age -d` still recovers everything.

### 2.1 The package

| Path | What it is | Encrypted under | Work factor | Plaintext |
| --- | --- | --- | --- | --- |
| `store.multipass/` | The package, named by `--store` or `MULTIPASS_STORE`, by default `~/.multipass/store.multipass`. A directory with mode 0700. | | | |
| `key.<gen>.age` | A key file, normally the only one | Your passphrase | 18 (`age::DEFAULT_WORK_FACTOR`) | § 2.2 |
| `store.<gen>.<random>.age` | A store file, normally the only one. `<gen>` names the key file whose key encrypts it. | The text of generation `<gen>`'s vault key | 10 (new `age::VAULT_WORK_FACTOR`) | A whole store, in format 3 |
| `moved.<gen>.<random>.age` | A move record, present only while an old single-file store sits beside the package (§ 2.6) | Generation `<gen>`'s vault key, like a store file | 10 | A snapshot of the old store's text, and the SHA-256 of the old file's bytes |
| `.<name>.tmp` | A file being written; every reader ignores it | | | |

`<gen>` and `<random>` are each 16 random bytes from `crypto::random::fill`, written as 32 lower-case hex digits. They are random rather than derived from the key, so a file name reveals nothing about a key, and no code outside `src/crypto` computes anything from one. Every file is written under its `.tmp` name, flushed to disk, and renamed into place, and the directory is flushed after the rename, so a reader sees a whole file or none, and a file exists only once it is durable.

Finder shows a directory as one item only when an installed app declares its extension as a package type. Until the passkeys plan's Mac app declares `.multipass`, Finder shows the package as an ordinary folder. That costs nothing: iCloud Drive, Dropbox, git, and Time Machine already sync, copy, and back up a folder as a unit, and multipass never needs Finder's view. The README tells you to move or copy the whole folder, never one file out of it.

### 2.2 The key file

```text
multipass-key 1
generation 3f9a1c2e8b7d4f6a0c5e9b1d2f3a4c5e
created 1764160000
passphrase-set 1763000000
key mXHnHUSvp+wCWtqvVrFcsN82rLveCB+L/s0F/V5yi9E
retired 7c1e9a3b5d2f4e6a8c0b1d3f5a7c9e2b 1761200000 1763000000 Qm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE
```

| Line | Meaning |
| --- | --- |
| `generation` | This key's id, the `<gen>` in its file names |
| `created` | When the key was made, in Unix seconds. The key expires 21 days later. |
| `passphrase-set` | When the passphrase that encrypts this file was set, in Unix seconds. `passwd` sets it to now, and every other rotation copies it from the key file it replaces, so it tells which of two passphrases is newer. |
| `key` | The vault key: 32 random bytes as 43 characters of unpadded base64, from a constant-time `crypto::base64::encode`. Its text is the passphrase of this generation's store files, so multipass never decodes it. |
| `retired` | An earlier generation's id, when it was made, when it was retired, and its key. Kept for 90 days, so a store file that another Mac wrote under that key before it heard of the rotation can still be opened and merged. |

### 2.3 How a store opens at a passphrase prompt

1. `open` asks for the passphrase and lists the package. It ignores `.tmp` files and the `.DS_Store` file Finder leaves in a folder, without a warning, and warns about any other file that does not match `key.*.age`, `store.*.age`, or `moved.*.age`, without touching it. Names that match loosely, such as a sync service's `store.3f9a….age 2`, are not adopted.
2. It decrypts every key file with the passphrase. The newest by `created`, with ties going to the larger `generation`, is current. Every key, current or retired, from every file it opened, goes into one set of known keys.
3. When no key file opens, the passphrase is wrong, and `open` fails with `wrong passphrase, or the store is damaged`, as today. When some open and others do not, the others are under a passphrase set by `passwd` on another Mac, possibly a newer one. `open` says so, naming the files, and asks `Other passphrase: `. With both passphrases, it rotates under the one whose key files carry the later `passphrase-set`, so a `passwd` always wins over a rotation that raced it. Without the other passphrase, it opens read-only: the command can read what it merged, but nothing saves, rotates, or compacts, and it says `another passphrase was set on another Mac; type it to save`. So a lineage under an older passphrase never keeps writing.
4. It decrypts every store file whose generation it has a key for, and merges them with `Store::merge`. A store file with an unknown generation is left alone, with a warning. When it finds key files but no store file it can open, it fails with `the store is still syncing; try again shortly`. A file that disappears while it reads, because another Mac deleted it after merging it, makes it list the package again, up to three times.
5. It rotates (§ 2.5) when the current key is 14 or more days old, when it opened more than one key file, or when the command is `passwd` or `rekey`.
6. When the package holds a move record, it opens it with its generation's key and runs the old-file check in § 2.6. A move record under a generation it has no key for is left alone, with a warning, like a store file.
7. When it did not rotate, and it merged more than one store file, it compacts: it writes one new store file under the current key, holding the merged store, and then deletes the store files it read.
8. The command runs on the merged store.

When a rotation or compaction cannot write to the package, as in a read-only backup, a command that only reads warns `could not write to <package>: …` and runs on the merged store, and a command that saves fails with that error before it asks for anything more.

A merge or a compaction deletes only files it read, and only after its own new file is durable. A file another Mac writes meanwhile was not read, so it survives. When a deletion reaches another Mac before the file that replaced it, that Mac briefly sees fewer entries, never wrong ones, and they come back when the newer file arrives, because a merge only adds what it finds.

### 2.4 How a save works

1. The command, or session unlock's agent, merges every store file it can open, as § 2.3 steps 4 and 7 describe, using the keys it holds.
2. It applies the change, stamped as the mergeable-store plan's § 2.2 describes.
3. It writes the result as a new `store.<current gen>.<random>.age`, and then deletes the store files it read.

No save modifies a file. Two Macs that save at the same moment each write their own new file, each delete only what they read, and the next open merges both. A save never needs the passphrase, only the current key.

### 2.5 Rotation

| Trigger | Passphrase for the new key file |
| --- | --- |
| A prompt finds the current key 14 or more days old | The one you just typed |
| A prompt finds more than one key file | The one you just typed, or, when the key files are under two passphrases, the one with the later `passphrase-set` (§ 2.3 step 3) |
| `passwd`, every time | The new one |
| `multipass rekey`, for a suspected leak | The one you just typed |
| `init`, to make the first key | The new one |

A rotation runs four steps, each a durable write or delete:

1. Make a new vault key, and write `key.<new>.age` holding it, `created` now, and as `retired` lines every key in the known set that is under 90 days retired. `passphrase-set` is now for `passwd` and `init`, and otherwise the newest one among the key files it opened.
2. Write `store.<new>.<random>.age` holding the merged store, and, when the package holds a move record, a new `moved.<new>.<random>.age` with the same snapshot and hash.
3. Delete the store files and the move record it read.
4. Delete the key files it opened, whose keys now live on as `retired` lines.

A crash at any point leaves a package that opens. After step 1, the next prompt finds two key files, merges everything it can open with both, and rotates again. After step 2 or 3, the leftover files merge into the same content. A `passwd` cut short before step 4 leaves the old key file under the old passphrase, which § 2.3 step 3 handles.

#### 2.5.1 How Macs share the 21 days

The key's `created` time travels in the key file, so every Mac that syncs the package sees the same expiry.

1. A key is made on day 0. You type the passphrase on your laptop on day 15. The key is 15 days old, so the laptop rotates, and the new files sync.
2. On day 16 you type it on your desktop. The desktop finds a key a day old and does not rotate.
3. If nobody types it for a month, the key expires on day 21, and the first prompt anywhere afterwards rotates.
4. Two Macs that rotate before hearing of each other each write their own key file and store file. The next prompt on either finds two key files, merges every store file under both, and rotates once more into one generation. Nothing is lost, because neither Mac deleted a file it had not read.
5. A Mac that saves under an old key after another Mac rotated writes a store file under the old generation. The next prompt opens it with the `retired` key in the new key file and merges it, for up to 90 days.

One case cannot be avoided. Your desktop prompts on day 13, so it does not rotate, and its session holds the day-0 key. Your laptop prompts on day 15 and rotates. The desktop's session ends when it sees the new generation, two days after you last typed the passphrase there. It happens at most once per rotation. It cannot be avoided because age requires an scrypt stanza to be the only stanza in a file, so a store file cannot be encrypted under both the old key and the new one at once, and new files must use the new key for rotation to retire the old one.

### 2.6 Moving a store into a package

A store from before this project is a single file encrypted under the passphrase. When `--store` or `MULTIPASS_STORE` names such a file, or neither is set and `~/.multipass/store.age` exists but `~/.multipass/store.multipass` does not, `open` asks for the passphrase and moves it:

1. It builds the package in `<name>.multipass.tmp`, with a key file from `init`'s rotation, one store file holding the old store read as format 3 with `modified 0`, and a move record, `moved.<gen>.<random>.age`. The move record is under the vault key like a store file, and holds a snapshot of the old store text and the SHA-256 of the old file's bytes, which are ciphertext and so public.
2. It renames the directory to `<name>.multipass`, so the package appears whole or not at all.
3. It leaves the old file where it is, and prints `Moved <old file> into <package>` to stderr.

The old file stays because another Mac, still on an older multipass or not yet synced, may save to it after the move, and deleting it would lose that save. While both exist, every passphrase prompt checks the old file:

| What the prompt finds | What it does |
| --- | --- |
| The old file's SHA-256 matches the move record | Nothing. When the old file has also been unchanged for 30 days, it deletes the old file and then the move record. |
| The hash differs | Something saved to the old file after the move. It decrypts the old file with the passphrase and compares each entry with the move record's snapshot. An entry added or changed since the snapshot goes into the package stamped now, and an entry removed since the snapshot gets a tombstone stamped now. It then writes a new move record with the new snapshot and hash, deletes the previous record, and warns `<old file> changed after the move; merged its changes`. |
| An old file but no move record, such as one a sync service brought back after it was retired | It imports the old file's entries with `modified 0`, so it adds what the package lacks and overrides nothing, writes a move record, and warns. |

Rotation re-encrypts the move record under the new key (§ 2.5 steps 2 and 3). Compaction leaves it alone, since it merges only store files. Session unlock's agent leaves it alone too, because the check needs the passphrase to open the old file, so it runs only at a passphrase prompt. When `--store` or `MULTIPASS_STORE` still names the old file, multipass opens the package beside it and prints `note: <old file> moved to <package>; update MULTIPASS_STORE or --store`. A crash before step 2 leaves a `.tmp` directory, which the next attempt removes and rebuilds. An older multipass cannot open a package, and the README says so.

The package and the move ship as two pull requests, the package first. Until the move lands, a build refuses a single-file store with `<path> is a single-file store from an earlier multipass, which this build cannot open`, and changes nothing on disk.

### 2.7 Recovering the store with stock age

Normally the package holds one key file and one store file:

```sh
cd ~/.multipass/store.multipass
age -d key.*.age      # prints the key file; copy the text after "key "
age -d store.*.age    # paste that text at age's passphrase prompt
```

With several key files, decrypt each and use the one with the largest `created`. A store file's middle part names its generation, so `store.3f9a….age` opens with the `key` or `retired` line for generation `3f9a…`. With several store files, each holds a whole store, and for each entry the version with the largest `modified` is the current one.

### 2.8 What the vault key exposes

| Who | Today | With a vault key |
| --- | --- | --- |
| Someone with a copy of the package, guessing offline | Runs scrypt at work factor 18 for every guess at the passphrase | The same, on a key file. The store's key is random and 256 bits, so guessing it is hopeless despite its low work factor. |
| Someone who learns the passphrase and has the files | Reads the store | The same, through a key file |
| Someone who copies a vault key, for example from session unlock's agent | Not possible | Reads every store file written under that key, here, in sync, and in backups. The next rotation retires it, at most 21 days later, or at once after `rekey`, and it opens nothing written after that. It does not reveal the passphrase. |
| Someone with an old passphrase and an old key file, such as from a git history or a backup | After `passwd`, reads only copies of the store from before the change | The same, because `passwd` rotates. The old key file's keys open only store files from before the change. |
| Someone who watches the synced files | Sees one file and when it changes | Sees how many files there are and when each appears, so how often you save and roughly when keys rotate. A sync service sees this anyway. The entry names, count, and sizes stay inside each store file. |
| A future quantum computer | Nothing to attack: passphrase mode is symmetric | The same. Every file uses only scrypt and ChaCha20-Poly1305. |

### 2.9 Changes by file

| File | Change |
| --- | --- |
| `src/age.rs` | Adds `VAULT_WORK_FACTOR`, 10. `encrypt` and `decrypt` are unchanged, and `decrypt` already accepts work factors 1 to 22. |
| `src/crypto/base64.rs` | `encode` stops indexing `ALPHABET` with the data, and maps each 6-bit value to its character with masked arithmetic, because it now encodes the vault key. `decode` keeps its `match`, because nothing secret passes through it here; the passkeys plan changes it too. |
| `src/vault.rs` | New. `VaultKey` and `KeyFile`, whose `Debug` output shows no key text; generating keys and ids; reading and writing the key file's text; listing a package; `open`, `save`, `rotate`, and `compact`, with the steps in § 2.3 to § 2.5; and the move in § 2.6. It keeps keys as text, as `src/store.rs` treats secrets. |
| `src/store.rs` | The single-file `Store::load` and `Store::save` go. `Store::encrypt` and `Store::decrypt` stay, and `src/vault.rs` calls them with a key's text at `VAULT_WORK_FACTOR`. The durable write, a temporary file then a flush, a rename, and a flush of the directory, moves to a shared `write_private_durable`, used for every file in the package. |
| `src/main.rs` | The default store path becomes `~/.multipass/store.multipass`, and `--store` and `MULTIPASS_STORE` name a package, with the old-file handling in § 2.6. `open` calls `vault::open` and keeps the known keys for the save. `init` and `passwd` rotate. Adds `rekey`. |
| `README.md` | The recovery section shows § 2.7. "Sync between machines" replaces "edit on one machine at a time" with "edits to different entries merge; the newer edit to the same entry wins", says to sync and move the whole package, and says each Mac asks for the passphrase at least 7 and at most 21 days apart. "Why it is built this way" says the passphrase unlocks a random vault key that rotates, and the files are still only passphrase-mode age. Documents the move, `rekey`, the 90-day key and 120-day tombstone limits, and that older builds cannot open a package. Warns, beside the install and upgrade instructions, not to go back to a multipass from before this release once the store has moved into a package: for up to 30 days an older multipass still reads and saves the old file beside it, whose changes the package then merges, but after the old file is retired an older multipass finds no file at `~/.multipass/store.age`, so every command fails, and its `init` would create a new, empty store beside the package. Its first paragraph, which says multipass keeps everything "in one file", says a package of files instead. |
| `AGENTS.md` | "Keep the store readable by stock age" changes to § 2.7's steps, and the hand check runs them. "Write the store atomically" becomes: never modify a file in the package; write each file once, durably, under a new name. Adds `src/vault.rs` to the places that keep secrets as text. Its first paragraph, which calls multipass "a Rust CLI over one age file", says a package of age files instead. |

## 3. Why this design

- **Files that are never modified.** Every sync service handles a new file well and a file changed on two machines badly. If no file is ever changed, there is nothing to reconcile: each Mac adds files and removes only files it has read, and the merge makes sense of whatever is there. That holds without relying on iCloud's, Dropbox's, or git's own conflict handling.
- **A new file per save, rather than one file per Mac.** Files per Mac would still be rewritten in place, so a Mac's own saves could race each other's sync, and a Mac's identity would have to be stored and kept unique. A new name per save needs neither.
- **One store per file, not one file per entry.** Files per entry would show anyone who sees the synced folder how many entries you have, how long each secret is, and when you change each one, and recovery would mean decrypting every file by hand. A whole store in each file hides all of that.
- **Generations in file names, with random ids.** The name tells each reader which key opens a file without trying every key. A random id says nothing about the key, and needs no cryptography outside `src/crypto`.
- **Retired keys carried forward for 90 days.** A Mac that saves under an old key before it hears of a rotation is normal with sync, so its file must stay openable. Carrying the old key inside the new key file, under the passphrase, keeps it openable without keeping the old key file, and drops it 90 days after it is retired. A key is retired at the first prompt after it expires, which can be long after day 21 when nobody prompts, so a store file it can still open may be older than any fixed bound. So `open` gives the mergeable store a cutoff for tombstones: the earlier of 120 days ago and the `created` time of the oldest key it knows, current or retired. No tombstone is dropped while a key that could open an older store file remains.
- **Key files are immutable too.** Rotation writes a new key file and deletes old ones only after their keys live on in it, so two Macs rotating at once produce two key files that the next prompt merges, never one overwriting the other.
- **21 days, rotating from 14.** The key needs a deadline every Mac agrees on, so session unlock's sessions end together and a copied key goes stale. A restart already costs a prompt, and rotating early at any prompt in the last 7 days means expiry never forces a second prompt within 7 days of the last on that Mac.
- **`passwd` rotates.** Changing the passphrase because someone may know it must lock them out of the current store, and that means a new key. The cost is that other Macs' sessions end, which is rare.
- **The vault key as text, and work factor 10.** age's passphrase mode takes a passphrase, so a store file's passphrase is the key's base64 text, and multipass never decodes it. Nobody can guess a random 256-bit key, so stretching it buys nothing, and work factor 10, about a millisecond, keeps saves and merges fast. scrypt stays only because passphrase mode is what stock `age -d` opens. `age::decrypt` and the reference `age` crate both accept it.
- **A package.** The files must travel together: a store file without its key file opens for no one. A directory keeps them together through sync, backups, and moves, and gives multipass one place to list. Naming it `.multipass` lets the Mac app later make Finder show it as one item.
- **Reuse.** Every file goes through `age::encrypt` and `age::decrypt`, every merge through `Store::merge`, and every write through one `write_private_durable`. `init`, `passwd`, `rekey`, expiry, and reconciling two key files share one `rotate`.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass init`, then `ls -la ~/.multipass/store.multipass` | Mode 0700, holding one `key.<gen>.age` and one `store.<gen>.<random>.age` with the same `<gen>`, both mode 0600 |
| § 2.7's steps with both the reference Go `age` and the `age` crate | The key file prints `multipass-key 1`, `generation`, `created`, and `key`, and the store file prints `multipass 3` and the entries |
| `multipass add x`, then `ls` the package | A different store file name than before, still one store file, and the same key file |
| `multipass passwd`, then `multipass list` with the new passphrase | Lists the entries. The key file has a new generation, its `retired` line names the old one, and the old passphrase opens nothing in the package. |
| Copy a package to a second directory. `multipass --store a add x` and `multipass --store b add y`. Copy each new store file into the other directory, then `multipass --store a list` | Lists both `x` and `y`, and `a` holds one store file again |
| As above, but `b` runs `multipass rekey` before `add y` | `a` finds two key files, lists both entries, and ends with one key file of a newer generation |
| As above, but `a` runs `rm x` and `b` edits `x` later | The later of the two changes wins |
| Point `MULTIPASS_STORE` at a single-file store written by today's multipass, then `multipass list` | Asks for the passphrase, lists the entries, prints `Moved …`, and a package sits beside the old file, which stays. A second `multipass list` prints the `note: … update MULTIPASS_STORE` line. |
| Copy the old file aside before the move, add an entry to the copy with an older multipass, copy it back over the old file, then `multipass list` | Warns `… changed after the move; merged its changes` and lists the new entry |
| A package holding a key file but no store file | Fails with `the store is still syncing; try again shortly` |

Tests that must fail before the change and pass after it. A test harness simulates sync with two package directories and a copier that applies one directory's new files and deletions to the other, in every interleaving of the steps below:

- **Two saves at once.** A adds `x` and B adds `y`, in every copy order. Both survive, and after one more open on each side both directories hold the same single store file content. Catches a save that deletes a file it did not read.
- **Edit against removal.** A edits `x` and B removes it, with B's stamp later, in every copy order. `x` is gone on both. Catches a tombstone lost in a copy.
- **Rotation against an old-key save.** A rotates while B saves under the old key, in every order. B's change survives on both, opened through A's `retired` line. Catches the lost-store hazard in § 1.
- **Two offline rotations.** A and B each rotate, then copy. The next prompt merges both generations, rotates once, and leaves one key file. Catches a key file that orphans another's store.
- **`passwd` against a rotation.** A runs `passwd` from P1 to P2 while B rotates under P1, in every copy order. After both sync, a prompt with only P1 opens read-only and saves nothing. With both, it rotates under P2, and afterwards P1 opens no key file. Catches an old passphrase that keeps a lineage writing.
- **A wrong passphrase.** With one key file, a typo fails with `wrong passphrase, or the store is damaged`, and never asks for another passphrase. Catches a typo read as a passphrase change.
- **A save to the old file after the move.** A moves a single-file store into a package while B, on an older build, adds `z` to the old file and removes `y`. A's next prompt has `z`, has a tombstone for `y`, and keeps the old file. After 30 unchanged days the old file is deleted. Catches a move that loses a save another Mac made.
- **Crash points.** A rotation, a compaction, and a move into a package, each stopped after every step, open with every entry intact. A `passwd` stopped after its first step opens read-only with the old passphrase, and with both passphrases rotates under the new one. Catches a step order that loses data.
- **Expiry boundaries.** A prompt with the key 13 days 23 hours old does not rotate, and at 14 days it does. An agent deadline is `created` plus 21 days. After a rotation, the next prompt does not rotate again. Catches early rotation that never fires, and rotation on every prompt.
- **Retired keys expire.** A store file under a generation retired 91 days ago is left alone with a warning; at 89 days it is merged. Catches a key kept forever, and one dropped too soon.
- **A move record.** A package holding a move record and an unchanged old file opens with no warning about either. A rotation leaves exactly one move record, under the new generation, with the same snapshot and hash. Catches multipass warning about its own file, and a rotation that drops the record and so loses track of the old file.
- **Foreign names.** A file named `store.<gen>.<random>.age 2` is warned about and left in place, and a `.tmp` file is ignored. Catches adopting a sync service's half-copied file.
- **`base64::encode`** still matches RFC 4648 after the masked rewrite, for every byte value, and `KeyFile`'s `Debug` output holds no key text.

## 5. Cost

Opening at a prompt runs scrypt at work factor 18 once per key file, normally one, about 300 ms as today, plus about a millisecond per store file at work factor 10. With compaction at every save and every prompt, a package normally holds one key file and one store file, and briefly one more store file per Mac that saved since the last merge. Below 16 files, an open stays well under half a second; beyond that it still works, a millisecond per store file. A save writes one file and deletes one or two. A rotation adds one key file write at work factor 18, about 300 ms, once in 7 to 21 days.

## 6. Open questions

None. Every decision here is the user's: the package, files that are never modified, one store per file, the 21-day key rotating from 14 days, rotation on `passwd`, and `rekey`.

## 7. Outcome

Built as two stacked pull requests on the mergeable store: the package, key file, saves, rotation, `passwd`, and `rekey` first, then the move from a single-file store. `src/vault.rs` holds both, and its tests drive two package directories through a copier that plays a sync service, in every order of the two sides' changes and syncs. The build settled these details, which the sections above leave open or state differently:

- **The move record's fields.** A move record holds `file`, the old store's file name in the package's directory, `sha256` of its bytes, `since`, the Unix second the hash was recorded, and the old store's decrypted text as the snapshot. The 30 unchanged days in § 2.6 count from `since`, not from the old file's modification time, which a sync service can change without changing the file.
- **The move keeps a format 3 store's stamps.** § 2.6 says the move reads the old store "as format 3 with `modified 0`". A store from formats 1 and 2 does read that way, but the mergeable store's release writes format 3 to the single file, with real stamps, tombstones, and history, and the move keeps them, so a removal made before the move stays a removal. An old file found without a move record still imports at `modified 0`, as § 2.6 says, so it adds only what the package lacks.
- **The old file is opened with every passphrase typed at the prompt.** A `passwd` after the move puts the package under the new passphrase while an older multipass on another Mac keeps the old file under the old one, so the check tries the passphrase and, when one was asked for, the other passphrase. When neither opens a changed old file, the prompt warns and leaves the record as it is.
- **A move record whose old file is gone is deleted.** Another Mac retired the old file, so nothing remains to check.
- **`.DS_Store` is ignored without a warning**, like a `.tmp` file, because Finder writes one into any folder it shows, and the package is an ordinary folder until the passkeys plan's app declares it.
- **A read-only open says so.** When some key file stays closed, the command prints `opened read-only; another passphrase was set on another Mac`, and a command that saves fails before it asks for anything, with § 2.3's message.
- **The 21-day expiry has no effect in the CLI yet.** Rotation from day 14 means a prompt never finds a key older than 14 days without replacing it, so only session unlock's agent, which ends its session at expiry, reads the 21 days. Its plan carries that check.
- **The by-hand checks.** A store made by `main`'s multipass moved at the first `list`, printed `Moved …`, and the next `list` printed the `note: … update MULTIPASS_STORE` line. A save to the old file by that older multipass merged with `… changed after the move; merged its changes`. The reference `age` crate, version 0.12.1, in a scratch project outside the repository, decrypted the key file with the passphrase, the store file and the move record with the key's text, and printed `multipass-key 1`, `multipass 3`, and `multipass-moved 1`. Stock `age` was not installed, so the Go implementation was not run.
