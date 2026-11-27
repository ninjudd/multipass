---
status: ready
priority: now
---

# Vault key

The passphrase unlocks a random vault key kept in its own small age file, and the vault key encrypts the store, so saving needs only the vault key and changing the passphrase rewrites only the small file.

## 1. Problem

Today the passphrase encrypts the store directly. `Store::save` runs scrypt at work factor 18 on the passphrase, about 300 ms, and the age format requires a fresh salt and file key for every file. So every save needs the passphrase itself, and `passwd` re-encrypts the whole store.

That blocks session unlock, which `docs/projects/session-unlock` plans next. Its agent must save while you are not typing, and an agent that saves under today's design must hold the passphrase, which opens every copy of the store ever written under it. A key between the passphrase and the store lets the agent hold that key instead, and lets the passphrase change without touching the store. Commands in this project still ask for the passphrase every time; only the layout changes.

## 2. Solution

Each store becomes two ordinary age passphrase files. The key file, `store.key.age` beside `store.age`, is encrypted under your passphrase at work factor 18, as the store is today, and holds a random 256-bit vault key written as base64 text. The store, `store.age`, is encrypted with that text as its passphrase, at work factor 10. A random 256-bit key needs no stretching, so scrypt stays there only because age's passphrase mode is what lets stock `age -d` open the file. Opening runs the slow scrypt once on the key file, then the fast one on the store. Saving runs only the fast one, with a fresh salt and file key as the age format requires. `passwd` rewrites only the key file. A new `multipass rekey` replaces the vault key and rewrites both files, in an order that a crash cannot break. A store written by today's multipass keeps opening, and upgrades to the two files at its first passphrase prompt. Stock `age -d` still recovers everything, in two steps.

### 2.1 The two files

| File | Path | Encrypted under | Work factor | Plaintext |
| --- | --- | --- | --- | --- |
| Key file | The store path with its final `.age` replaced by `.key.age`, so `~/.multipass/store.age` gets `~/.multipass/store.key.age`. A store path that does not end in `.age` gets `.key.age` appended. | Your passphrase | 18 (`age::DEFAULT_WORK_FACTOR`) | `multipass-key 1`, then one or two lines of `key <vault key>` |
| Store | `--store` or `MULTIPASS_STORE`, unchanged | The text of a vault key from the key file | 10 (new `age::VAULT_WORK_FACTOR`) | The store text, `multipass 2`, unchanged |

A vault key is 32 bytes from `crypto::random::fill`, encoded by `crypto::base64::encode` as 43 characters of unpadded base64, as the example below shows. The store's passphrase is those 43 characters as bytes, so multipass never decodes the key. A key file holds two `key` lines only while `rekey` runs (§ 2.4).

```text
multipass-key 1
key mXHnHUSvp+wCWtqvVrFcsN82rLveCB+L/s0F/V5yi9E
```

The key file sits beside the store, so a folder you sync carries both. Sync both files, and edit on one machine at a time, as today. The store text keeps its `multipass 2` header, because its contents do not change.

### 2.2 How a store opens

1. `open` asks for the passphrase and reads both files.
2. It decrypts the key file with the passphrase. A wrong passphrase fails here with `wrong passphrase, or the store is damaged`, as today.
3. It tries each `key` line, in order, as the store's passphrase. The first that decrypts the store is the vault key, and `open` returns the store with it. When the file held two lines, `open` rewrites it with only that one (§ 2.4).
4. When the key file is missing, the store is from before this project. `open` decrypts the store with the passphrase directly, then upgrades it (§ 2.5).
5. When no `key` line opens the store, `open` tries the passphrase on the store directly, which finishes an upgrade that a crash interrupted (§ 2.5). When that fails too, it fails with `the key file does not open the store; if they are still syncing, try again shortly`.

### 2.3 How a save works

`Store::save` takes the vault key instead of the passphrase, and encrypts the store with it at work factor 10, with a fresh salt and file key, through the existing temporary file and rename. It never touches the key file. A save no longer needs the passphrase, which is what lets session unlock's agent save while you are not typing.

### 2.4 `init`, `passwd`, and `rekey`

| Command | What it writes, in order |
| --- | --- |
| `init` | A new vault key. The key file, then the store, each through a temporary file and rename. |
| `passwd` | After it checks the old passphrase on the key file, the key file again under the new passphrase, with the same vault key. The store stays as it is. |
| `multipass rekey` | Asks for the passphrase, opens the store, and makes a new vault key. 1. The key file with two lines, the old key then the new. 2. The store under the new key. 3. The key file with only the new key. Each write is a temporary file and a rename. |

A crash at any point in `rekey` leaves files that open. Before step 2, the old key still opens the store; after it, the new key does. `open` (§ 2.2 step 3) tries both lines, uses whichever works, and rewrites the key file with only that line, since it has the passphrase in hand. A rekey that stopped before step 2 is then undone, and running `rekey` again finishes the job.

### 2.5 Upgrading a store from before this project

A store with no key file is encrypted under the passphrase, as today's multipass writes it. At its first passphrase prompt, whatever the command, `open` upgrades it: it makes a vault key, writes the key file, then writes the store under the vault key, each through a temporary file and a rename. It prints `Upgraded <store> to use a vault key in <key file>` to stderr. A crash after the key file is written leaves a key file that does not open the store, which § 2.2 step 5 detects and finishes.

After the upgrade, an older multipass cannot open the store: it reports a wrong passphrase, because the store's passphrase is now the vault key. The README says so under the upgrade note.

### 2.6 Recovering the store with stock age

The README's recovery section becomes two steps:

```sh
age -d ~/.multipass/store.key.age    # prints the key file; copy the text after "key "
age -d ~/.multipass/store.age        # paste that text at age's passphrase prompt
```

When the key file shows two `key` lines, an interrupted `rekey` left them, and one of the two opens the store.

### 2.7 What the vault key exposes

| Who | Today | With a vault key |
| --- | --- | --- |
| Someone with a copy of the store files, guessing offline | Runs scrypt at work factor 18 for every guess at the passphrase | The same, on the key file. The store's key is random and 256 bits, so guessing it is hopeless despite its low work factor. |
| Someone who learns the passphrase and has the files | Reads the store | The same, through the key file |
| Someone who copies the vault key, for example from session unlock's agent | Not possible | Reads every copy of the store written under that key, here, in sync, and in backups, until `rekey`. The key does not reveal the passphrase. |
| Someone with an old passphrase and an old copy of the key file, such as from a git history or a backup, after `passwd` | The current store is under the new passphrase, so they cannot read it | The old key file still yields the vault key, and the vault key still opens the current store. `passwd` does not revoke it; `rekey` does. |
| A future quantum computer | Nothing to attack: passphrase mode is symmetric | The same. Both files use only scrypt and ChaCha20-Poly1305. |

So the README tells you to run `multipass rekey` after `passwd` whenever you change the passphrase because someone may know it, and whenever the vault key may have leaked.

### 2.8 Changes by file

| File | Change |
| --- | --- |
| `src/age.rs` | Adds `VAULT_WORK_FACTOR`, 10. `encrypt` and `decrypt` are unchanged, and `decrypt` already accepts work factors 1 to 22. |
| `src/crypto/base64.rs` | `encode` stops indexing `ALPHABET` with the data, and maps each 6-bit value to its character with masked arithmetic, because it now encodes the vault key. The RFC 4648 tests stay and must still pass. `decode` keeps its `match`, because nothing secret passes through it here; the passkeys plan changes it too. |
| `src/vault.rs` | New. `VaultKey`, which holds the 43-character text and never prints it in `Debug`; `VaultKey::generate`; the key file's path rule; reading and writing the key file's text; and the `rekey` and upgrade steps in § 2.4 and § 2.5. The key file's parsing treats the key as text, as `src/store.rs` treats secrets. |
| `src/store.rs` | `Store::save(path, &VaultKey)` encrypts at `VAULT_WORK_FACTOR`. New `Store::open(path, passphrase) -> (Store, VaultKey)` follows § 2.2, including the upgrade. `Store::load` goes, and its one caller moves to `Store::open`. |
| `src/main.rs` | `open` returns the vault key in place of the passphrase, and every save passes it. `init` and `passwd` write as § 2.4 says. Adds `rekey` to the commands and `USAGE`. |
| `README.md` | The recovery section shows § 2.6. "Sync between machines" says to sync the key file with the store. "Why it is built this way" says the passphrase unlocks a random vault key, and the store is still only passphrase-mode age. The upgrade note says older builds cannot open an upgraded store. Documents `rekey` and the advice in § 2.7. |
| `AGENTS.md` | "Keep the store readable by stock age" changes from one `age -d` to the two steps in § 2.6, and the hand check runs both. Adds `src/vault.rs` to the places that keep secrets as text. |

## 3. Why this design

- **Two stock age files, not a new format.** Wrapping the vault key in its own age file keeps every byte on disk readable by `age -d`, which AGENTS.md requires, and keeps multipass in passphrase mode with no public-key step. A custom wrapper inside one file would need its own parser and would break stock-age recovery.
- **The vault key as text.** age's passphrase mode takes a passphrase, so the store's passphrase is the key's base64 text. Using the text as it is means multipass never decodes the key, and the key file shows exactly what to paste into `age -d`.
- **Work factor 10 for the store.** scrypt slows down guessing a weak passphrase. Nobody can guess a random 256-bit key, so stretching it buys nothing, and work factor 10, about a megabyte and a millisecond, keeps saves instant. The tests already use 10, and `age::decrypt` accepts it. The reference `age` crate sets no lower bound either.
- **The key file sits beside the store.** `--store` and `MULTIPASS_STORE` keep meaning the store file, so nobody's setup changes, and a synced folder carries both files. Making `MULTIPASS_STORE` name a directory would break every existing setting.
- **Two `key` lines during `rekey`.** Two files cannot be renamed together, so the key file holds both keys while the store changes over. Every crash point then leaves a key that opens the store, without a journal or a lock file.
- **Upgrade at the first prompt.** The passphrase is in hand only at a prompt, and session unlock's agent needs a vault key from its first session. Waiting for the first save would leave stores that are only read on the old layout indefinitely.
- **`passwd` keeps the vault key.** Changing the passphrase without touching the store was the point of the design. The cost is the old-key-file row in § 2.7, which `rekey` covers.
- **Its own plan, before session unlock.** It changes the on-disk layout, recovery, and sync advice, and it is worth having alone, for an instant `passwd` and for `rekey`. Session unlock builds on it.
- **Reuse.** The key file and the store both go through `age::encrypt` and `age::decrypt`, and both writes go through the temporary-file-and-rename route in `Store::save`, which `src/vault.rs` calls for the key file rather than repeating it.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass init`, then `ls -l ~/.multipass` | `store.age` and `store.key.age`, both mode 0600 |
| `age -d ~/.multipass/store.key.age` with the passphrase, then `age -d ~/.multipass/store.age` with the text after `key ` | The first prints `multipass-key 1` and one `key` line, the second prints `multipass 2` and the entries. Run with both the reference Go `age` and the `age` crate. |
| `multipass add x`, then `age -d` on the store with the vault key | The store holds `x`, and the key file's bytes did not change |
| `multipass passwd`, then `multipass list` with the new passphrase | Lists the entries, and the store's bytes did not change |
| `multipass rekey`, then `multipass list` | Lists the entries. The key file holds one `key` line, different from before, and the old key no longer opens the store. |
| Point `MULTIPASS_STORE` at a store written by today's multipass, then `multipass list` | Asks for the passphrase, lists the entries, prints `Upgraded …`, and a key file now sits beside the store |
| `multipass list` on a store and key file that do not match | Fails with `the key file does not open the store; if they are still syncing, try again shortly` |

Tests that must fail before the change and pass after it:

- **Opening tries each key line.** A key file with the old and new keys opens a store written under either, and afterwards holds only the key that opened it. A key file with a single wrong key fails with the syncing message. Catches a rekey that crashed between steps and left the store unopenable.
- **`rekey` survives a crash at each step.** A test runs the steps in § 2.4 one at a time in a temporary directory, stops after each, and opens the store with the passphrase. Every stop opens, and the entries match. Catches a write order that leaves the two files disagreeing.
- **Upgrade, and an upgrade cut short.** A store written under the passphrase opens and leaves a key file and a store under the vault key. A key file written with the store left on the passphrase also opens, and finishes the upgrade. Catches a crash in the upgrade that locks you out.
- **`passwd` leaves the store's bytes alone**, and the new passphrase opens the key file while the old one does not. Catches a `passwd` that rewrites the store or keeps the old passphrase.
- **The key file path rule**: `store.age` gives `store.key.age`, `a.b.age` gives `a.b.key.age`, and `vault` gives `vault.key.age`. Catches a key file that lands somewhere sync does not carry.
- **`base64::encode` still matches RFC 4648** after the masked rewrite, for every byte value. Catches a masked mapping that is off at a range boundary, such as 25 to 26 or 61 to 62.
- **`VaultKey`'s `Debug` output** holds no key text. Catches a key that reaches an error message.

## 5. Cost

Opening runs scrypt at work factor 18 once, on the key file, the same 300 ms as today, plus a millisecond at work factor 10 for the store. A save drops from 300 ms to about a millisecond. `passwd` costs two runs at work factor 18, opening and rewriting the key file, and no longer rewrites the store. `rekey` costs three: one to open the key file and two to write it.

## 6. Open questions

None. Every decision here is the user's: the two files, the low work factor for the store, `passwd` keeping the vault key, and `rekey`.
