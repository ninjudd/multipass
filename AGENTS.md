# Project guidelines

multipass is a single-user password manager: a Rust CLI over one age file encrypted with a passphrase, with no dependencies. [README.md](README.md) describes how it works for someone using it; keep it true when behaviour changes.

## No dependencies

multipass has no dependencies, not even dev-dependencies, and that is a feature people choose it for. CI fails if `cargo tree` shows anything but multipass itself.

- **Do not add a crate**, for code or for tests, without the maintainer's explicit approval in the pull request. Write the code instead.
- **Every primitive lives in `src/crypto`** and is checked against the official test vectors from its specification: FIPS 180-4 for SHA-256, RFC 4231 for HMAC, RFC 5869 for HKDF, RFC 7914 for PBKDF2, scrypt and Salsa20/8, RFC 8439 for ChaCha20 and Poly1305, and RFC 4648 for base64. A change to a primitive keeps those tests and adds any vector that covers the changed path.
- **Never branch on secret data or index memory with it**, apart from scrypt's data-dependent lookups, which the algorithm requires. Compare MACs and tags with `crypto::ct_eq`.
- **Stay in age's passphrase (scrypt) mode.** Adding public-key recipients would bring back the quantum exposure the design avoids.

## Compatibility with age

- **Keep the store readable by stock age.** `age -d` on the store must always print the store text. `testdata/reference-*.age` were written by the reference implementation (the `age` crate, version 0.12.1) and `age::tests` must keep decrypting them. Those files hold only a fixed byte pattern under the published test passphrase in `age.rs`; they are the one exception to never committing an encrypted file.
- **Check the other direction by hand when the format code changes.** The tests cannot run reference age without a dependency, so encrypt a file with multipass and decrypt it with `age -d` (or the `age` crate in a scratch project outside this repository) before handing the change over.
- **Change the store text only by bumping the `multipass 1` header** and teaching `Store::from_text` to read the old version.

## Rules that protect secrets

- **Never put a secret or passphrase in argv, an environment variable, a log line or an error message.** Passphrases come from `/dev/tty` through `tty::read_hidden`; secrets come from a hidden prompt or stdin. Store errors name a line number, never the line.
- **Write the store atomically.** `Store::save` writes a temporary file with mode 0600 and renames it into place; keep any new write path on that route.
- **Never commit a store or any other encrypted file**, even a test one with fake secrets. Tests build their stores in memory or in a temporary directory. The reference fixtures under `testdata/` are the one exception, as the age section says.

## Tests

Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` before handing work over; CI runs the same three plus the dependency check. Tests use scrypt work factor 10 so they stay fast. The CLI always uses `age::DEFAULT_WORK_FACTOR` (18), about a third of a second in a release build.

The CLI reads passphrases from `/dev/tty`, so it cannot be driven from a plain pipe. To exercise it without a terminal, use `expect` against a release build, and point `--store` at a temporary file.
