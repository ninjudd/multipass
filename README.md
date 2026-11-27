# multipass

multipass is a minimal password manager with no dependencies and no sharing. It keeps your secrets, and the setup keys for your one-time passwords, in a small folder of files encrypted with [age](https://age-encryption.org) and unlocked by a passphrase you choose, and it does nothing else: no accounts and no server.

Use it beside a full password manager, not instead of one. Keep shared and everyday logins in something like 1Password. Keep the few secrets you never want on someone else's server in multipass, such as recovery codes, seed phrases, and the master password itself.

Every line of multipass is in this repository, cryptography included: about 1,000 lines of cryptography and 5,800 of everything else, small enough to read in a day. It uses no third-party crates, so the only code you trust beyond this repository is the Rust toolchain, its standard library, and two of macOS's own frameworks, each loaded only when it is needed: AppKit when you pass `--clip`, and LocalAuthentication when a session agent starts, for Touch ID.

> [!WARNING]
> multipass is new and has not been audited. Its cryptography is written by hand and checked against the official test vectors and against files from the reference age implementation, but no one outside the project has reviewed it.

## Why it is built this way

- **One passphrase, no public keys.** age's passphrase mode derives a key with scrypt and encrypts with ChaCha20-Poly1305. Both are symmetric, so there is no public-key step for a future quantum computer to break. Your passphrase unlocks a random 256-bit vault key, and the vault key encrypts the store. multipass replaces the vault key at least every 21 days and on every `passwd`, and every file is still a passphrase-mode age file.
- **No dependencies.** SHA-1, SHA-256, SHA-512, HMAC, HKDF, PBKDF2, scrypt, ChaCha20-Poly1305, HOTP, TOTP, base32, and base64 are each implemented in `src/crypto` and tested against the official vectors from their specifications. `cargo tree` lists multipass and nothing else, and CI fails if that changes.
- **A standard file format.** Every file in the store is an ordinary age file, compatible with the reference implementation in both directions. If multipass breaks or disappears, two `age -d` commands still print everything as plain text, as [Recover the store without multipass](#recover-the-store-without-multipass) shows.
- **Files that are never changed.** A save writes a new file and then deletes the files it read. It never rewrites a file, so a sync service has no two versions of one file to reconcile, and changes made on two Macs merge.
- **Nothing readable on disk.** Entry names live inside the encrypted files, so the files do not reveal which accounts you have.
- **Secrets never touch argv.** Passphrases come from a hidden terminal prompt, and secrets come from a prompt or stdin, so neither shows up in `ps` or your shell history.

## Install

Install from a checkout with `install.sh`. It needs [Rust](https://rustup.rs), builds the checkout with `cargo build --release --locked --offline`, which takes a few seconds because multipass has no dependencies, and installs the binary as `~/.local/bin/multipass`:

```sh
git clone https://github.com/ninjudd/multipass
cd multipass
./install.sh
```

The installer prints one row for each step. When `~/.local/bin` is not on your `PATH`, it prints the line to add to your shell's startup file rather than editing the file itself, and when another `multipass` comes first on your `PATH`, such as Canonical's Multipass for Ubuntu virtual machines, it says so. It records what it installed in `~/.local/share/multipass-install/receipt`, and it never touches your stores or `~/.multipass`.

```sh
./install.sh status      # what is installed, and whether it matches the checkout
./install.sh uninstall   # remove the binary the installer wrote, keeping your stores
```

To upgrade, pull the checkout and run `./install.sh` again. A rerun that would install the same bytes leaves the file alone. For a copy the installer installed from a release, `multipass upgrade` downloads the newest release's installer with `/usr/bin/curl`, checks its attestation with `gh` when `gh` is installed, and runs it; `multipass upgrade 0.2.0` installs a given release, and `multipass upgrade --check` only says whether a newer release is out. `upgrade` is the only command that reaches the network, and only when you type it. `uninstall` removes only a file that still matches the receipt, so it never deletes a `multipass` you replaced by hand. Set `MULTIPASS_BIN_DIR` to install somewhere other than `~/.local/bin`; a later rerun installs to the same place without it.

> [!WARNING]
> Once this multipass has moved your store into a package, do not go back to a multipass from before the package, with `multipass upgrade <version>` or an older checkout. For up to 30 days an older multipass still reads and saves the old `store.age` beside the package, and the package merges its changes. After the old file is retired, an older multipass finds no store at `~/.multipass/store.age`, so every command fails, and its `init` would create a new, empty store beside the package.

## Use

```sh
multipass init                                   # create ~/.multipass/store.multipass
multipass add github.com --username octocat      # prompts for the secret
multipass add example.com --generate --clip      # makes a new password and copies it
multipass get github.com --clip                  # copies the secret for 30 seconds
multipass get github.com --field username
multipass list
multipass rm github.com                          # recoverable for 30 days
multipass passwd                                 # change the passphrase
multipass rekey                                  # replace the vault key now
```

The first command asks for the passphrase, and on a Mac with Touch ID or an Apple Watch, later commands ask for a touch instead, as [Stay unlocked between commands](#stay-unlocked-between-commands) describes. `generate` and `upgrade` open no store, so they ask for neither. To use a different store, set `MULTIPASS_STORE` or pass `--store` with the path of its folder.

The store is a folder, `~/.multipass/store.multipass`, that holds a key file, `key.<generation>.age`, encrypted under your passphrase, and a store file, `store.<generation>.<id>.age`, encrypted under the vault key in the key file. Finder shows it as an ordinary folder. Move or copy the whole folder, never one file out of it, because a store file opens only with the key file of its generation.

A store from an earlier multipass is a single file, `~/.multipass/store.age`. The first command that asks for your passphrase moves it into `~/.multipass/store.multipass` and prints `Moved … into …`. To move a store elsewhere, point `--store` or `MULTIPASS_STORE` at the old file, and its package appears beside it, with the same name ending in `.multipass`. multipass leaves the old file where it is, because another Mac on an older multipass may still save to it, and merges any change made to it at the next prompt. If you ran `passwd` since, and the older multipass saves under your earlier passphrase, the prompt asks for that passphrase to merge the change. When the folder holding the old file cannot be written, as in a read-only backup, commands that only read use the old file as it is, with a warning, and commands that save fail before they ask for anything. Once the old file has gone 30 days unchanged, multipass deletes it. While `--store` or `MULTIPASS_STORE` still names the old file, multipass opens the package and reminds you to update it. A multipass from before the package cannot open one.

When a passphrase prompt finds the vault key 14 or more days old, multipass replaces it: it writes a new key file and a new store file, and deletes the old ones. So the key in use is always under 21 days old. When a key replacement, a merge of several store files, or a merge of a change to an old single-file store cannot write to the folder, as in a read-only backup, `get`, `list`, `history` and `otp` still read the store, after a `could not write to <folder>` warning, and commands that save fail with that error before they ask for anything. When neither is due, a read prints no warning, and a command that saves fails with the same error once it saves. `passwd` always replaces the key, so your old passphrase opens nothing written afterwards, and `rekey` replaces it at once, for example when you think someone copied it. Neither reveals or changes your passphrase.

`--clip` on `get`, `otp`, and `generate` copies the value instead of printing it, and `--clip` on `add --generate` copies the password it stores, which it never prints. Either way, multipass clears the clipboard 30 seconds later, unless you have copied something else since. It marks the value as concealed and as this Mac only, so Universal Clipboard does not send it to your other Apple devices, and clipboard-history apps that honor the marking skip it. Until it clears, any app running on this Mac can still read it: the markings only keep it off your other devices and out of the history apps that honor them. `--clip` works only on macOS. Piping to `pbcopy` also works, but `pbcopy` cannot mark the value, so it syncs and lands in clipboard history.

## Make new passwords

`multipass generate` prints a new password and stores nothing. `multipass add <name> --generate` makes one and stores it as the entry's secret without printing it; add `--clip` to copy it, so you can paste it into the site's form. Both print the password's strength on stderr, in bits: the base-2 logarithm of how many passwords the options could have produced, each equally likely.

```console
$ multipass generate
k7#Rv2!mQe9_Tz4@pLw8
multipass: random characters, 20 from 94, each set present: 130.9 bits

$ multipass generate --words 5
oxidize-tattered-flier-rebound-anyone
multipass: memorable, 5 words from 7,776 with hyphens: 64.6 bits

$ multipass generate --pin 6
480213
multipass: PIN, 6 digits: 19.9 bits -- weak for a password you cannot rate-limit
```

| Option | Default | Effect |
| --- | --- | --- |
| `--length <n>` | `20` | Random characters, from 4 to 128. Uppercase letters, lowercase letters, digits, and symbols each appear at least once. |
| `--no-uppercase`, `--no-lowercase`, `--no-digits`, `--no-symbols` | | Leaves a set out. |
| `--symbols <chars>` | all 32 ASCII punctuation characters | The symbols to use, for a site that accepts only some. |
| `--exclude <chars>` | | Characters never to use. |
| `--no-lookalikes` | | Leaves out `0`, `O`, `o`, `1`, `l`, `I`, and `\|`. |
| `--words [<n>]` | `5` | Memorable words instead, from 3 to 15, drawn from the EFF's large word list of 7,776 words. |
| `--separator <sep>` | `hyphen` | With `--words`: `hyphen`, `space`, `period`, `comma`, `underscore`, `digit`, or `digit-or-symbol`. The last two draw a new character for each gap. |
| `--capitalize <how>` | `none` | With `--words`: `first` capitalizes every word, and `one` capitalizes one word chosen at random. |
| `--pin [<n>]` | `6` | A PIN instead, from 4 to 64 digits. |

Every character, word, and separator is drawn from `/dev/urandom` without bias, and the strength line counts exactly the passwords that meet the options. A password under 64 bits gets a warning: that is too weak to survive an attacker who can guess offline, though a PIN that a bank's servers rate-limit is still fine.

## Stay unlocked between commands

On a Mac with Touch ID or a paired Apple Watch, a command that asks for the passphrase also starts a background agent, `multipass __agent`, that keeps the store unlocked. Each later `get`, `list`, `history`, `otp`, `add`, `rm`, or `restore` asks only for a touch of Touch ID or a press on the watch, on a sheet that names the entry, such as "multipass is trying to read github.com". One touch covers one request, and the agent hands over or changes only the entry the sheet names. `init`, `passwd`, and `rekey` always ask for the passphrase.

```sh
multipass get github.com     # Passphrase: … and an agent starts
multipass get github.com     # a Touch ID sheet, then the password
multipass status             # unlocked until 2026-12-17 14:32:00 UTC
multipass lock               # Locked: the next command asks for the passphrase
```

The session ends when the vault key expires, at most 21 days after it was made, on a restart, on `multipass lock`, when you cancel a sheet or leave it for 60 seconds, when another Mac replaces the vault key, and when multipass is upgraded. The next command then asks for the passphrase and says why, such as `Passphrase (you declined a request): `. When neither Touch ID nor a watch can answer, as with the lid closed, a command asks for the passphrase and the session stays. Over SSH no agent is asked or started.

What this trades: a program running as you, an AI coding agent included, still cannot read or change an entry, because each request puts a sheet on your screen that only a finger or the watch can approve. Cancel any sheet you did not expect, which ends the session. A person past your Mac's own lock screen can use the store with an enrolled finger, without the passphrase, until the session ends. The agent holds the vault key in memory for the whole session. It refuses debuggers and leaves no core file, and its own copy of the keys is locked out of swap and wiped when the session ends. The copies it makes to open the store for each request are not wiped. Root or a kernel exploit could copy the key. If you think the Mac was compromised, run `multipass rekey`. Set `MULTIPASS_NO_AGENT=1` to be asked for the passphrase every time.

## Get an earlier password back

Each entry keeps the secrets it used to hold, and the one-time password setup keys it used to hold, each with the time it was replaced. `history` lists those times, and never the values. `get --previous <n>` prints or copies one, counting from 1 for the most recently replaced.

```sh
$ multipass history github.com
changed    2025-11-26 10:00:00 UTC
secret 1   2025-11-26 10:00:00 UTC
secret 2   2025-03-02 18:41:07 UTC
otp 1      2025-08-14 09:12:55 UTC
$ multipass get github.com --previous 1 --clip            # the secret replaced on 26 November
$ multipass get github.com --previous 1 --field otp       # the setup key replaced in August
```

An entry keeps its last 10 earlier secrets, or every one it replaced in the past year, whichever is more, and the same for setup keys, including one replaced with `otp --set --force` or removed with `otp --clear`. After `rm`, the entry no longer appears in `list` or `get`, but for 30 days the store keeps it whole: its secret, username, notes, and one-time password. `restore` brings it back, and `history` and `get --previous` still find its secrets:

```sh
multipass restore github.com
```

`restore` refuses when an entry by that name exists. Adding the name again with `add` instead starts a new entry, which keeps the removed secrets as its history but not the username or notes. After 30 days multipass no longer finds the removed entry or its secrets, `restore` refuses, and an entry added under the name starts with no history. The store file itself drops them the next time multipass writes it, so until any command saves, `age -d` still shows them. History lives inside the encrypted store, like everything else.

## Keep one-time passwords

An entry can hold a one-time password setup key beside its secret, username, and notes, and `otp` prints the entry's current code. When a site shows a QR code for an authenticator app, it usually offers the setup key as text too: either a base32 key such as `JBSW Y3DP EHPK 3PXP`, or an `otpauth://totp/` URI.

```sh
printf 'JBSW Y3DP EHPK 3PXP' | multipass otp github.com --set   # or paste it at the prompt
multipass otp github.com --clip                               # copies the code for 30 seconds
multipass get github.com --field otp                          # the stored otpauth:// URI
multipass otp github.com --clear                              # remove the one-time password
```

`--set` creates the entry when none exists, so an entry can hold only a one-time password. It refuses to replace a one-time password the entry already has, because a replaced setup key cannot be recovered and losing it can lock you out of the account; pass `--force` to replace it. It keeps an `otpauth://` URI exactly as you give it, and turns a bare key into one. Codes use SHA-1, SHA-256, or SHA-512, 6 to 8 digits, and a period of up to 300 seconds, as the URI says. Counter-based (`hotp`) one-time passwords are not supported. `add --force` replaces an entry's secret, username, and notes, and keeps its one-time password.

A setup key stored next to its password means that anyone with your passphrase holds both factors for that account. multipass suits best the setup keys of accounts whose password lives elsewhere, such as in 1Password, so that no single vault holds both.

## Move a secret out of 1Password

When stdin is piped, `add` reads the secret from it, so you can pipe a secret straight from `op read`:

```sh
op read "op://Private/Seed phrase/password" | multipass add seed-phrase
```

1Password keeps the secret in its item history and backups after the move. To take the secret out of 1Password's reach, change it after the move and store only the new value in multipass.

## Sync between machines

The store is ciphertext, so it is safe to sync with iCloud Drive, Dropbox, or a private git repository. Sync the whole `store.multipass` folder, and point `MULTIPASS_STORE` at the synced copy.

You can change the store on two Macs at once. Each save adds its own file and deletes only the files it read, and the next command on either Mac merges what it finds, entry by entry. Edits to different entries merge, and the newer edit to the same entry wins. The older edit's secret is not lost: it becomes history, so `get --previous` finds it.

When one Mac replaces the vault key while another still saves under the old one, the next prompt opens the other Mac's file with the old key, which the new key file keeps for 90 days. A removal reaches every copy as long as each one syncs within 120 days, or longer while an older vault key is still kept. A copy that comes back after longer than that, by some other path such as a restored backup, can bring back an entry you removed.

If you change the passphrase on one Mac while another replaces the vault key under the old one, multipass asks for the other passphrase the next time it finds both. With both, it keeps the newer passphrase. Without the other one, it opens the store read-only and saves nothing.

## Recover the store without multipass

Install any age implementation. Decrypt the key file with your passphrase, then the store file with the vault key it prints:

```sh
brew install age
cd ~/.multipass/store.multipass
age -d key.*.age      # prints the key file; copy the text after "key "
age -d store.*.age    # paste that text at age's passphrase prompt
```

The key file prints as text, with the vault key on its `key` line:

```text
multipass-key 1
generation 3f9a1c2e8b7d4f6a0c5e9b1d2f3a4c5e
created 1764160000
passphrase-set 1763000000
key mXHnHUSvp+wCWtqvVrFcsN82rLveCB+L/s0F/V5yi9E
```

Normally the folder holds one key file and one store file. With several key files, decrypt each and use the one with the largest `created`. The middle part of a store file's name is its key's generation, so `store.3f9a….age` opens with the `key` line, or a `retired` line, whose generation is `3f9a…`. With several store files, each holds a whole store, and for each entry the version with the largest `modified` is the current one. A `store.age` beside the folder is the single-file store from before the move: it holds the store as it was then, plus whatever an older multipass saved to it since, so recover from the folder, not from it.

age prints the store as text: each entry's name on its own line, then its fields indented by a tab. `modified` is when the entry last changed, in milliseconds since 1970. Each `previous-secret` and `previous-otp` line holds an earlier value after the time it was replaced. A removed entry is marked `deleted`, and its fields follow, with its secrets as history, until multipass writes the store 30 or more days after the removal.

```text
multipass 3
github.com
	modified 1764151200000
	secret hunter2
	username octocat
	otp otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
	previous-secret 1764151200000 hunter1
old-bank
	modified 1764160000456
	deleted
	secret correct horse battery staple
	username me@example.com
	previous-secret 1764160000456 correct horse battery staple
```

If you lose the passphrase, no one can recover the store. That is the point.

## Not built yet

- **Export to 1Password.** Send an entry to 1Password with `op item create`, and delete it locally once it lands.
- **Memory wiping.** Wipe secrets from memory once a command is done.
- **Echo after Ctrl-C.** Restore terminal echo when you press Ctrl-C at a passphrase prompt. Until then, if your terminal stops showing what you type, run `stty echo` or `reset`.

## License

MIT. The word list in `src/crypto/wordlist/eff_large.txt` is the [EFF's large word list](https://www.eff.org/dice) by the Electronic Frontier Foundation, with its dice numbers removed, under the [Creative Commons Attribution 4.0 International license](https://creativecommons.org/licenses/by/4.0/) that [EFF's copyright policy](https://www.eff.org/copyright) gives its original material.
