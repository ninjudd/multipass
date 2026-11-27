---
status: ready
priority: now
---

# One-time passwords

An entry can hold a one-time password setup key next to its secret, username, and notes, and `multipass otp <name>` prints that entry's current code.

## 1. Problem

multipass stores each entry as three text fields: `secret`, `username`, and `notes` (`src/store.rs`, `Entry`). Many accounts also use time-based one-time passwords (TOTP, RFC 6238): an authenticator app holds a setup key, usually shown as a QR code or an `otpauth://` URI, and turns it into a six-digit code that changes every 30 seconds.

You can paste a setup key into `notes` today, but multipass cannot turn it into a code, so you still need a separate authenticator app. And because the key sits in free text, nothing checks that it is valid when you save it, and no command can find it later.

This matters most for accounts whose password lives in 1Password. Keeping their setup keys in multipass means no single vault holds both factors.

## 2. Solution

Each entry gains an optional `otp` field that holds an `otpauth://totp/` URI. A new `otp` command reads the field, computes the current code from the setup key and the system clock, and prints it. The field lives in the same entry as the password, username, and notes, so one name groups everything about an account. An entry may hold only a one-time password, for an account whose password is kept elsewhere. To make that possible, `secret` becomes optional, and every entry must hold a `secret`, an `otp`, or both. The store text moves to format 2 to carry the new field, and multipass still reads format 1.

### 2.1 How a code is produced

1. You run `multipass otp github.com`.
2. multipass asks for the passphrase and decrypts the store, as every command does.
3. It parses the entry's `otp` URI into a setup key, an algorithm, a digit count, and a period.
4. It divides the current Unix time by the period to get a counter, and computes HOTP (RFC 4226) on that counter: an HMAC of the counter under the setup key, cut down to `digits` decimal digits.
5. It prints the code to stdout with a trailing newline only on a terminal, like `get`. So `multipass otp github.com | pbcopy` copies exactly the code. When stderr is a terminal, it also prints `expires in 17s` there.

### 2.2 Setting and clearing the field

| Command | Effect |
| --- | --- |
| `multipass otp <name>` | Prints the current code. Fails with `<name> has no one-time password` when the entry has no `otp`. |
| `multipass otp <name> --set` | Reads an `otpauth://totp/` URI or a bare base32 setup key from stdin when piped, or from a hidden prompt, and stores it in the entry's `otp`. It creates the entry when none exists, and keeps the entry's other fields when one does. A bare key is stored as `otpauth://totp/<label>?secret=<KEY>`, where `<KEY>` is the key decoded and encoded again by `crypto::base32`, so it is in upper case without spaces or padding. The label is the entry name percent-encoded: every byte outside RFC 3986's unreserved characters (letters, digits, `-`, `.`, `_`, and `~`) becomes `%XX`, so a name holding a space, `#`, `?`, `/`, or `%` still builds a valid URI. |
| `multipass otp <name> --clear` | Removes the `otp` field. It fails when that would leave the entry with neither a secret nor an `otp`; use `rm` for that. |
| `multipass get <name> --field otp` | Prints the stored URI, so you can move the key to another authenticator. |
| `multipass add <name> --force` | Replaces the secret, username, and notes, and keeps an existing `otp`. |

The setup key never appears in argv, for the same reason secrets never do.

### 2.3 The `otpauth` URI multipass accepts

The URI takes the form `otpauth://totp/<label>?secret=<base32>&issuer=…&algorithm=…&digits=…&period=…`. multipass stores the URI exactly as you entered it, once it has checked the URI, so `age -d` recovers the same URI that any authenticator app can import.

| Part | Accepted values | Default |
| --- | --- | --- |
| Type | `totp` only. `hotp` is rejected, because a counter-based code would have to rewrite the store on every use. | |
| `secret` | Base32, case-insensitive, with optional `=` padding. It must decode to at least 1 byte. | Required |
| `algorithm` | `SHA1`, `SHA256`, `SHA512` | `SHA1` |
| `digits` | 6, 7, or 8 | 6 |
| `period` | 1 to 300 seconds | 30 |
| Label, `issuer` | Any percent-encoded text. multipass keeps them but does not use them. | |

### 2.4 Store format 2

Format 2 is format 1 plus an `otp` field, and `secret` becomes optional. multipass always writes format 2, and reads both formats. An older multipass that reads only format 1 refuses a format 2 store with its existing message: `the store uses format 2, but this multipass reads format 1`.

```text
multipass 2
github.com
	secret hunter2
	username octocat
	otp otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
aws-root
	otp otpauth://totp/AWS?secret=KRSXG5CTMVRXEZLU
```

| `Entry` field | Type | Rule |
| --- | --- | --- |
| `secret` | `Option<String>` | At least one of `secret` and `otp` is present |
| `username` | `Option<String>` | Unchanged |
| `notes` | `Option<String>` | Unchanged |
| `otp` | `Option<String>` | A URI that passes the checks in § 2.3 when it is read or set |

### 2.5 Changes by file

| File | Change |
| --- | --- |
| `src/crypto/sha1.rs` | New. SHA-1 (FIPS 180-4), with the FIPS and RFC 3174 vectors as tests. |
| `src/crypto/sha512.rs` | New. SHA-512 (FIPS 180-4), with 64-bit words and a 128-byte block, and the FIPS vectors as tests. |
| `src/crypto/hmac.rs` | New. `hmac` moves here from `sha256.rs` with its RFC 4231 tests, and becomes generic over a small `Digest` trait, defined here, that `Sha1`, `Sha256`, and `Sha512` implement. The trait gives each hash's block length, 64 bytes for SHA-1 and SHA-256 and 128 for SHA-512, so one HMAC pads the key correctly for all three. |
| `src/crypto/sha256.rs` | `Sha256` implements `Digest`, and `hmac` and its tests move to `hmac.rs`. HKDF and PBKDF2 stay here, call `hmac::<Sha256>`, and stay SHA-256. |
| `src/crypto/base32.rs` | New. A base32 decoder (RFC 4648 § 6) that ignores case, spaces, and `=` padding, and rejects any other character, and an encoder that writes upper case without padding. A setup key is secret, so neither branches on a character or indexes memory with one. The decoder computes each character's 5-bit value, and whether it is a symbol, a space or `=`, or invalid, with masked arithmetic rather than a `match` or a lookup table. It writes each output byte through a masked pass over every output position, because where a byte lands depends on how many spaces came before it, and it branches once, on an invalid flag gathered over the whole input, after the last character. The encoder maps each 5-bit value to its character with masked arithmetic. The decoded length, which is the key's length, is the only thing either reveals. |
| `src/crypto/hotp.rs` | New. HOTP (RFC 4226) and TOTP (RFC 6238), generic over the `Digest` trait: `hotp(key, counter, digits)` and `totp(key, unix_seconds, period, digits)`, with the RFC 4226 Appendix D and RFC 6238 Appendix B vectors as tests. Dynamic truncation (RFC 4226 § 5.4) takes its offset from the MAC's last byte, so it selects the four bytes at that offset with a masked pass over every offset rather than indexing the MAC with it. |
| `src/crypto/mod.rs` | Registers the five new modules. |
| `src/otp.rs` | New. Parses and checks an `otpauth` URI, builds one from a bare key and an entry name with the name percent-encoded as the label, and computes `code(at_unix_seconds)` by passing the decoded key, digits, and period to `crypto::hotp::totp` under the URI's algorithm. The caller passes in the time, so tests control the clock. The module holds no cryptography of its own. |
| `src/store.rs` | `Entry.secret` becomes optional, and `Entry` gains `otp`. Writes format 2 and reads formats 1 and 2. Rejects an entry with neither `secret` nor `otp`, and an `otp` that fails the URI checks. `Error::UnsupportedFormat` says `this multipass reads formats 1 and 2` instead of hard-coding format 1, so a later format names the formats this build reads. |
| `src/main.rs` | Adds the `otp` command with `--set` and `--clear`, adds `otp` as a `get --field` value, and makes `add --force` keep `otp`. Updates `USAGE`. |
| `README.md` | Documents the `otp` command, the field, and the advice in § 3 about which setup keys belong in multipass. Adds SHA-1, SHA-512, base32, HOTP, and TOTP to the hand-written primitives under "Why it is built this way", and shows `multipass 2` in the Recovery example. |
| `AGENTS.md` | Adds SHA-1 and SHA-512 (FIPS 180-4), HOTP (RFC 4226), TOTP (RFC 6238), and base32 (RFC 4648) to the list of required test vectors. |

## 3. Why this design

- **One entry per account.** The `otp` field sits beside the password, username, and notes, so `list` shows one name per account. A second entry such as `github.com-otp` would split one account across two names that nothing ties together.
- **Store the URI, not just the key.** The URI carries the algorithm, digit count, and period that some sites change from the defaults. Storing it verbatim means `age -d` gives back something any authenticator app can import.
- **Constant-time key handling.** `AGENTS.md` forbids branching on secret data or indexing memory with it, and the setup key and its MAC are secret. So the base32 code and dynamic truncation use masked passes instead of the `match` in `base64::value` and the indexed read that RFC 4226's reference code uses. Inputs are a few dozen bytes, so a pass over every position costs nothing noticeable. Storing a bare key through the encoder, rather than upper-casing it and removing spaces by hand, keeps that normalization branch-free too.
- **Reuse the existing HMAC.** `hmac` in `src/crypto/sha256.rs` already implements RFC 2104 over a 64-byte block. Making it generic over the hash adds SHA-1 and SHA-512 without a second HMAC, and moving it to `hmac.rs` keeps SHA-256's module from serving the other two hashes. SHA-1 is weak for collisions, but HMAC-SHA1 is not broken, and RFC 6238 and nearly every site still use it.
- **Every algorithm the URI format defines.** The `otpauth` format allows SHA-1, SHA-256, and SHA-512, and multipass supports all three, so no site's setup key is turned away. SHA-512 needs its own hash core with 64-bit words, about 100 lines, tested like the others. Its 128-byte block is why the `Digest` trait carries a block length instead of HMAC assuming 64.
- **No HOTP.** A counter-based code changes the counter on every use, so each `otp` call would have to re-encrypt and save the store.
- **Format 2 instead of tolerating unknown fields.** The format 1 reader rejects any field it does not know, which keeps a typo or a damaged store from passing silently. Bumping the version keeps that strictness, and the old binary's message says exactly what happened.
- **Both factors in one place is a choice you make.** A setup key stored next to its password means anyone with the passphrase holds both factors. The README says so, and recommends multipass for the setup keys of accounts whose password lives elsewhere.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `printf 'JBSW Y3DP EHPK 3PXP' \| multipass otp demo --set`, then `multipass otp demo` | The same code that `oathtool --totp -b JBSWY3DPEHPK3PXP` prints in the same 30-second window |
| `multipass otp github.com --set` on an entry with a secret and username, then `multipass get github.com` | The secret is unchanged, and `get --field otp` prints the URI |
| `printf JBSWY3DPEHPK3PXP \| multipass otp 'Chase Bank #2' --set`, then `multipass get 'Chase Bank #2' --field otp` | Prints `otpauth://totp/Chase%20Bank%20%232?secret=JBSWY3DPEHPK3PXP` |
| `printf 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512' \| multipass otp x --set`, then `multipass otp x` | The same code that `oathtool --totp=sha512 -b JBSWY3DPEHPK3PXP` prints in the same 30-second window |
| `multipass otp aws-root --clear` on an entry with no secret | Fails, and the entry keeps its `otp` |
| `multipass list` on a store that a format 1 multipass wrote | Opens. The next save writes format 2. |
| `age -d` on a store after `otp --set` | Shows `multipass 2` and the entry's `otp` line holding the URI exactly as entered |

Tests that must fail before the change and pass after it:

- **`sha1` against the FIPS 180-4 and RFC 3174 vectors** (`""`, `"abc"`, the 448-bit message, and a million `a`s fed in uneven pieces). Catches a wrong round constant, rotation, or padding length.
- **`sha512` against the FIPS 180-4 vectors** (`""`, `"abc"`, the 896-bit message, and a million `a`s fed in uneven pieces). Catches a 32-bit operation left in the 64-bit core, and a length field written in 8 bytes where SHA-512 needs 16.
- **HMAC-SHA-512 against RFC 4231**, test cases 1 and 6. Catches an HMAC that pads the key to 64 bytes for a hash whose block is 128, and a long key that is not hashed first.
- **HOTP against RFC 4226 Appendix D**, counters 0 to 9. Catches an error in dynamic truncation, such as taking the offset from the wrong byte or forgetting to mask the top bit.
- **TOTP against RFC 6238 Appendix B**, the SHA-1, SHA-256, and SHA-512 rows at 8 digits. Each algorithm takes its own seed from the Appendix A reference code: the 20-byte ASCII `12345678901234567890` for SHA-1, that string repeated to 32 bytes for SHA-256, and to 64 bytes for SHA-512. Appendix B's text names only the 20-byte seed, and the SHA-256 and SHA-512 rows fail under it. Catches a wrong counter (seconds against milliseconds, or rounding), the wrong hash for `algorithm`, and a code that drops its leading zero (`07081804`).
- **base32 against the RFC 4648 § 10 vectors**, decoding and encoding, plus lower case, spaces in every position, and missing padding, and rejecting `0`, `1`, `8`, and `-`. Catches a setup key that copies from a site in lower case or in groups and then decodes to the wrong bytes, and a masked write that puts a byte at the wrong position after a space.
- **URI parsing**, table-driven. Accepts each default and each listed value, and rejects `hotp`, a missing `secret`, `digits=9`, `period=0`, and an unknown algorithm such as `MD5`. A bare key set under names holding a space, `#`, `?`, `/`, and `%` builds a URI that passes the checks and parses back to the same key. Catches a malformed key that is stored and only fails when you need the code, and a name that breaks the URI built from it.
- **Store format 2** round-trips an entry with all four fields, an entry with only `otp`, and awkward characters in the URI. It reads a literal format 1 store. It rejects an entry with neither `secret` nor `otp`, and an `otp` line holding a bad URI. Catches a writer and a reader that disagree, and an old store that stops opening.
- **Argument parsing** for `otp`, `--set`, `--clear`, and `get --field otp`. It rejects `--set` together with `--clear`, and `--set` on any other command.

## 5. Cost

Computing a code takes a few hash compressions, two for SHA-1 or SHA-256 and two 128-byte blocks for SHA-512, and is too small to measure. Every `otp` call still decrypts the store first, which takes about 300 ms at work factor 18 in a release build, the same as `get`. That is the cost the user feels, and this project does not change it. The planned session unlock would remove it.

## 6. Open questions

- **SHA-512 setup keys.** Decided: this project includes a hand-written SHA-512, so every algorithm the `otpauth` format defines works from the start.
- **Fields beyond the four.** Decided: entries hold exactly `secret`, `username`, `notes`, and `otp` in this project. Arbitrary named fields, such as security questions or a PIN, get a plan of their own later, with their own store format.

## 7. Background

- RFC 4226 defines HOTP, and RFC 6238 defines TOTP as HOTP with `counter = floor(unix_time / period)`. Google's "Key Uri Format" defines the `otpauth://` URI that QR codes encode. That format is a de facto standard, not an RFC, and it is where the defaults of SHA-1, 6 digits, and 30 seconds come from.
- Some authenticator apps ignore the `algorithm`, `digits`, and `period` parameters and always use the defaults. multipass honors them, so it can disagree with such an app on a site that changes them. The site is right in that case.
- `oathtool`, from the oath-toolkit Homebrew formula, computes TOTP codes from a base32 key. The manual acceptance check in § 4 uses it as an independent implementation. Nothing in the repository depends on it.
