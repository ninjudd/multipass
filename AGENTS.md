# Project guidelines

multipass is a single-user password manager: a Rust CLI over one age file encrypted with a passphrase. [README.md](README.md) describes how it works for someone using it; keep it true when behaviour changes.

## Rules that protect secrets

- **Never put a secret or passphrase in argv, an environment variable, a log line or an error message.** Passphrases come from `rpassword` on the terminal; secrets come from a hidden prompt or stdin. Error messages name entries, never their values, which is why `Error::Format` carries no detail from serde_json.
- **Use only age for cryptography.** Do not add another crypto crate or call a primitive directly. Stay in passphrase (scrypt) mode: adding public-key recipients would bring back the quantum exposure the design avoids.
- **Keep the store readable by stock age.** `age -d` on the store must always print the JSON. Change the JSON shape only by bumping `store::FORMAT` and teaching `Store::decrypt` to read the old format.
- **Write the store atomically.** `Store::save` writes a temporary file with mode 0600 and renames it into place; keep any new write path on that route.
- **Never commit a store**, even a test one with fake secrets. Tests build their stores in memory or in a `tempfile` directory.

## Tests

Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` before handing work over; CI runs the same three. Tests pass a scrypt work factor of 10 so they stay fast. The CLI never passes one, so real stores use age's default of about a second per unlock.

The CLI reads passphrases from `/dev/tty`, so it cannot be driven from a plain pipe. To exercise it by hand without a terminal, use `expect`, and point `--store` at a temporary file.
