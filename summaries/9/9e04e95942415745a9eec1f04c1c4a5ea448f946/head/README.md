# multipass

multipass is a minimal password manager with no dependencies and no sharing. It keeps your secrets, and the setup keys for your one-time passwords, in one file, encrypted with [age](https://age-encryption.org) under a passphrase you choose, and it does nothing else: no accounts and no server.

Use it beside a full password manager, not instead of one. Keep shared and everyday logins in something like 1Password. Keep the few secrets you never want on someone else's server in multipass, such as recovery codes, seed phrases, and the master password itself.

Every line of multipass is in this repository, cryptography included: about 1,000 lines of cryptography and 900 of everything else, small enough to read in a day. It uses no third-party crates, so the only code you trust beyond this repository is the Rust toolchain, its standard library, and, for `--clip`, macOS's own AppKit framework.

> [!WARNING]
> multipass is new and has not been audited. Its cryptography is written by hand and checked against the official test vectors and against files from the reference age implementation, but no one outside the project has reviewed it.

## Why it is built this way

- **One passphrase, no public keys.** age's passphrase mode derives a key with scrypt and encrypts with ChaCha20-Poly1305. Both are symmetric, so there is no public-key step for a future quantum computer to break.
- **No dependencies.** SHA-1, SHA-256, SHA-512, HMAC, HKDF, PBKDF2, scrypt, ChaCha20-Poly1305, HOTP, TOTP, base32, and base64 are each implemented in `src/crypto` and tested against the official vectors from their specifications. `cargo tree` lists multipass and nothing else, and CI fails if that changes.
- **A standard file format.** The store is an ordinary age file, compatible with the reference implementation in both directions. If multipass breaks or disappears, `age -d ~/.multipass/store.age` still prints everything as plain text.
- **Nothing readable on disk.** Entry names live inside the encrypted file, so the file does not reveal which accounts you have.
- **Secrets never touch argv.** Passphrases come from a hidden terminal prompt, and secrets come from a prompt or stdin, so neither shows up in `ps` or your shell history.

## Install

```sh
cargo install --path .
```

## Use

```sh
multipass init                                   # create ~/.multipass/store.age
multipass add github.com --username octocat      # prompts for the secret
multipass get github.com --clip                  # copies the secret for 30 seconds
multipass get github.com --field username
multipass list
multipass rm github.com
multipass passwd                                 # change the passphrase
```

Every command asks for the passphrase. To use a different file, set `MULTIPASS_STORE` or pass `--store`.

`--clip` on `get` and `otp` copies the value instead of printing it, and clears the clipboard 30 seconds later, unless you have copied something else since. It marks the value as concealed and as this Mac only, so Universal Clipboard does not send it to your other Apple devices, and clipboard-history apps that honor the marking skip it. `--clip` works only on macOS. Piping to `pbcopy` also works, but `pbcopy` cannot mark the value, so it syncs and lands in clipboard history.

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

The store is ciphertext, so it is safe to sync with iCloud Drive, Dropbox, or a private git repository. Point `MULTIPASS_STORE` at the synced copy. multipass does not merge changes made on two machines, so edit the store on one machine at a time.

## Recover the store without multipass

Install any age implementation and decrypt the file directly:

```sh
brew install age
age -d ~/.multipass/store.age
```

age prints the store as text: each entry's name on its own line, then its fields indented by a tab.

```text
multipass 2
github.com
	secret hunter2
	username octocat
	otp otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
```

If you lose the passphrase, no one can recover the store. That is the point.

## Not built yet

- **Export to 1Password.** Send an entry to 1Password with `op item create`, and delete it locally once it lands.
- **Session unlock.** Unlock once per session, the way `ssh-agent` does, instead of asking for the passphrase on every command.
- **Memory wiping.** Wipe secrets from memory once a command is done.
- **Echo after Ctrl-C.** Restore terminal echo when you press Ctrl-C at a passphrase prompt. Until then, if your terminal stops showing what you type, run `stty echo` or `reset`.

## License

MIT
