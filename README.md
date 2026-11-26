# multipass

multipass is a small password manager for one person. It keeps your secrets in a single file, encrypted with [age](https://age-encryption.org) using a passphrase you choose, and it does nothing else: no accounts, no server, no sharing.

It is meant to sit beside a full password manager, not replace it. Keep shared and everyday logins in something like 1Password, and keep the few secrets you never want on someone else's server (recovery codes, seed phrases, the master password itself) in multipass.

multipass has no dependencies. Every line of multipass, cryptography included, is in this repository: about 600 lines of cryptography and 600 of everything else, small enough to read in an afternoon. There are no third-party crates to compromise; what is left to trust is the Rust toolchain and its standard library.

> [!WARNING]
> multipass is new and has not been audited. Its cryptography is written by hand and checked against the official test vectors and against files from the reference age implementation, but no one outside the project has reviewed it.

## Why it is built this way

- **One passphrase, no public keys.** age's passphrase mode derives a key with scrypt and encrypts with ChaCha20-Poly1305. Both are symmetric, so there is no public-key step for a future quantum computer to break.
- **No dependencies.** SHA-256, HMAC, HKDF, PBKDF2, scrypt, ChaCha20-Poly1305 and base64 are each implemented in `src/crypto` and tested against the official vectors from their specifications. `cargo tree` lists multipass and nothing else, and CI fails if that ever changes.
- **A standard file format.** The store is an ordinary age file, compatible with the reference implementation in both directions. If multipass ever breaks or disappears, `age -d ~/.multipass/store.age` still prints everything as plain text.
- **Nothing readable on disk.** Entry names live inside the encrypted file, so the file does not even reveal which accounts you have.
- **Secrets never touch argv.** Passphrases come from a hidden terminal prompt and secrets from a prompt or stdin, so neither shows up in `ps` or your shell history.

## Install

```sh
cargo install --path .
```

## Use

```sh
multipass init                                   # create ~/.multipass/store.age
multipass add github.com --username octocat      # prompts for the secret
multipass get github.com | pbcopy                # copies exactly the secret
multipass get github.com --field username
multipass list
multipass rm github.com
multipass passwd                                 # change the passphrase
```

Every command asks for the passphrase. Set `MULTIPASS_STORE` or pass `--store` to use a different file.

`add` reads the secret from stdin when stdin is piped, which is how a secret moves out of 1Password today:

```sh
op read "op://Private/Seed phrase/password" | multipass add seed-phrase
```

Moving a secret out of 1Password does not remove it from 1Password's item history or backups. If the point of the move is to take the secret out of 1Password's reach, change it afterward and store only the new one here.

## Syncing

The store is ciphertext, so it is safe to sync with iCloud Drive, Dropbox or a private git repository. Point `MULTIPASS_STORE` at the synced copy. multipass does not merge, so edit on one machine at a time.

## Not yet

- Exporting an entry into 1Password with `op item create`, and deleting it locally once it lands.
- Unlocking once per session, the way `ssh-agent` does, instead of asking for the passphrase on every command.
- Copying to the clipboard directly and clearing it after 30 seconds.
- Wiping secrets from memory once a command is done.
- Restoring terminal echo if you press Ctrl-C at a passphrase prompt. Until then, type `stty echo` (or `reset`) if your terminal stops showing what you type.

## Recovery

If you lose multipass, install any age implementation and decrypt the file directly:

```sh
brew install age
age -d ~/.multipass/store.age
```

It prints the store as text: each entry's name on its own line, then its fields indented by a tab.

```text
multipass 1
github.com
	secret hunter2
	username octocat
```

If you lose the passphrase, the store cannot be recovered. That is the point.

## License

MIT
