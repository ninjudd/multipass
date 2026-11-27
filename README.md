# multipass

multipass is a minimal password manager with no dependencies and no sharing. It keeps your secrets, and the setup keys for your one-time passwords, in a small folder of files encrypted with [age](https://age-encryption.org) and unlocked by a passphrase you choose, and it does nothing else: no accounts and no server.

Use it beside a full password manager, not instead of one. Keep shared and everyday logins in something like 1Password. Keep the few secrets you never want on someone else's server in multipass, such as recovery codes, seed phrases, and the master password itself.

Every line of multipass is in this repository, cryptography included: about 1,000 lines of cryptography and 2,200 of everything else, small enough to read in a day. It uses no third-party crates, so the only code you trust beyond this repository is the Rust toolchain, its standard library, and, when you pass `--clip`, macOS's own AppKit framework, which multipass loads only then.

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

```sh
cargo install --path .
```

## Use

```sh
multipass init                                   # create ~/.multipass/store.multipass
multipass add github.com --username octocat      # prompts for the secret
multipass get github.com --clip                  # copies the secret for 30 seconds
multipass get github.com --field username
multipass list
multipass rm github.com                          # recoverable for 30 days
multipass passwd                                 # change the passphrase
multipass rekey                                  # replace the vault key now
```

Every command asks for the passphrase. To use a different store, set `MULTIPASS_STORE` or pass `--store` with the path of its folder.

The store is a folder, `~/.multipass/store.multipass`, that holds a key file, `key.<generation>.age`, encrypted under your passphrase, and a store file, `store.<generation>.<id>.age`, encrypted under the vault key in the key file. Finder shows it as an ordinary folder. Move or copy the whole folder, never one file out of it, because a store file opens only with the key file of its generation.

When a passphrase prompt finds the vault key 14 or more days old, multipass replaces it: it writes a new key file and a new store file, and deletes the old ones. So the key in use is always under 21 days old. `passwd` always replaces the key, so your old passphrase opens nothing written afterwards, and `rekey` replaces it at once, for example when you think someone copied it. Neither reveals or changes your passphrase.

`--clip` on `get` and `otp` copies the value instead of printing it, and clears the clipboard 30 seconds later, unless you have copied something else since. It marks the value as concealed and as this Mac only, so Universal Clipboard does not send it to your other Apple devices, and clipboard-history apps that honor the marking skip it. Until it clears, any app running on this Mac can still read it: the markings only keep it off your other devices and out of the history apps that honor them. `--clip` works only on macOS. Piping to `pbcopy` also works, but `pbcopy` cannot mark the value, so it syncs and lands in clipboard history.

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

Normally the folder holds one key file and one store file. With several key files, decrypt each and use the one with the largest `created`. The middle part of a store file's name is its key's generation, so `store.3f9a….age` opens with the `key` line, or a `retired` line, whose generation is `3f9a…`. With several store files, each holds a whole store, and for each entry the version with the largest `modified` is the current one.

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
- **Session unlock.** Unlock once per session, the way `ssh-agent` does, instead of asking for the passphrase on every command. The vault key is what makes this possible: an agent could hold it without holding the passphrase.
- **Memory wiping.** Wipe secrets from memory once a command is done.
- **Echo after Ctrl-C.** Restore terminal echo when you press Ctrl-C at a passphrase prompt. Until then, if your terminal stops showing what you type, run `stty echo` or `reset`.

## License

MIT
