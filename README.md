# multipass

multipass is a minimal password manager with no dependencies and no sharing. It keeps your secrets in one file, encrypted with [age](https://age-encryption.org) under a passphrase you choose, and it does nothing else: no accounts and no server.

Use it beside a full password manager, not instead of one. Keep shared and everyday logins in something like 1Password. Keep the few secrets you never want on someone else's server in multipass, such as recovery codes, seed phrases, and the master password itself.

Every line of multipass is in this repository, cryptography included: about 600 lines of cryptography and 600 of everything else, small enough to read in an afternoon. It uses no third-party crates, so the only code you trust beyond this repository is the Rust toolchain and its standard library.

> [!WARNING]
> multipass is new and has not been audited. Its cryptography is written by hand and checked against the official test vectors and against files from the reference age implementation, but no one outside the project has reviewed it.

## Why it is built this way

- **One passphrase, no public keys.** age's passphrase mode derives a key with scrypt and encrypts with ChaCha20-Poly1305. Both are symmetric, so there is no public-key step for a future quantum computer to break.
- **No dependencies.** SHA-256, HMAC, HKDF, PBKDF2, scrypt, ChaCha20-Poly1305, and base64 are each implemented in `src/crypto` and tested against the official vectors from their specifications. `cargo tree` lists multipass and nothing else, and CI fails if that changes.
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
multipass get github.com | pbcopy                # copies exactly the secret
multipass get github.com --field username
multipass list
multipass rm github.com
multipass passwd                                 # change the passphrase
```

Every command asks for the passphrase. To use a different file, set `MULTIPASS_STORE` or pass `--store`.

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
multipass 1
github.com
	secret hunter2
	username octocat
```

If you lose the passphrase, no one can recover the store. That is the point.

## Not built yet

- **Export to 1Password.** Send an entry to 1Password with `op item create`, and delete it locally once it lands.
- **Session unlock.** Unlock once per session, the way `ssh-agent` does, instead of asking for the passphrase on every command.
- **Clipboard.** Copy a secret to the clipboard directly, and clear the clipboard after 30 seconds.
- **Memory wiping.** Wipe secrets from memory once a command is done.
- **Echo after Ctrl-C.** Restore terminal echo when you press Ctrl-C at a passphrase prompt. Until then, if your terminal stops showing what you type, run `stty echo` or `reset`.

## License

MIT
