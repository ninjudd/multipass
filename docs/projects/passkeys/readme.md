---
status: draft
priority: now
---

# Passkeys

multipass holds passkeys in its store and signs you in with them in Safari and other Mac apps, through a small Mac app that macOS lists as a passkey provider.

## 1. Problem

A passkey is a WebAuthn credential: a P-256 key pair that a site creates for you, where the site keeps the public key and you keep the private key. To sign in, the browser asks the operating system for a signature. The system hands the request to a passkey provider, such as iCloud Keychain or 1Password, which finds the matching private key and signs.

multipass cannot be that provider. It is a command-line tool, and macOS sends passkey requests only to an AutoFill credential provider extension inside a signed app (`ASCredentialProviderViewController`, macOS 14 and later). It also stores only text fields, with nowhere to keep a private key, a credential ID, and the site it belongs to. So every passkey you create today lives in iCloud Keychain or 1Password. Passkeys are replacing passwords on more sites each year, so a multipass that cannot hold them guards a shrinking share of your accounts.

## 2. Solution

A new Mac app, `Multipass.app`, exists only to host a credential provider extension. The extension links the existing Rust store code as a static library, so the store keeps one implementation. It signs with Apple's CryptoKit, so multipass never implements elliptic-curve arithmetic itself. A passkey becomes a `passkey` field on an entry, beside the secret, username, notes, and one-time password, in store format 3. The CLI lists and removes passkeys. Only the extension creates them and signs with them, because only the extension receives the site's request.

This design depends on the answers to § 6. Until those are settled, this plan stays a draft.

### 2.1 How a sign-in works

1. A site calls `navigator.credentials.get()`. macOS shows its passkey sheet, which offers multipass among the providers.
2. You choose multipass. The system starts the extension and calls `prepareInterface(forPasskeyRegistration:)` for a new passkey, or its assertion counterpart for a sign-in.
3. The extension shows its own passphrase field, and decrypts the store through the Rust library. That takes about 300 ms.
4. For a sign-in, the extension finds the entry whose `passkey` matches the site's relying party ID and the requested credential ID, signs the authenticator data and client data hash with CryptoKit's `P256.Signing`, and returns an `ASPasskeyAssertionCredential`.
5. For a registration, the extension generates a key pair with CryptoKit, saves a new entry through the Rust library with the store's usual atomic save, and returns an `ASPasskeyRegistrationCredential` with "none" attestation.
6. The extension drops the decrypted store from memory and exits.

### 2.2 The `passkey` field

Format 3 adds one field, written on a single line as space-separated `key=value` pairs, each value base64 or escaped text:

```text
multipass 3
github.com
	username octocat
	passkey rp=github.com id=<base64 credential id> user=<base64 user handle> key=<base64 private key> created=2026-11-26
```

| Part | Meaning |
| --- | --- |
| `rp` | The relying party ID, the site's domain, which the system checks against the page |
| `id` | The credential ID that the extension generated at registration |
| `user` | The user handle that the site sent at registration |
| `key` | The 32-byte P-256 private key, as CryptoKit's raw representation |
| `created` | The registration date, for `list` |

The extension always reports a signature counter of 0, which the WebAuthn specification allows for keys that sync.

### 2.3 Changes by file

| Path | Change |
| --- | --- |
| `Cargo.toml` | Adds a `[lib]` target with `crate-type = ["staticlib", "rlib"]`, so the extension can link the store code. Still no dependencies. |
| `src/ffi.rs` | New. A C interface over `Store`: open with a passphrase, find a passkey, add an entry, save, and free. |
| `src/store.rs` | Format 3: the `passkey` field, and reading formats 1 to 3. |
| `src/main.rs` | `list` marks entries that hold a passkey; `get --field passkey` prints the site and creation date, never the key. |
| `mac/` | New. The Xcode project for `Multipass.app` and its extension, in Swift. It uses only Apple's frameworks: AuthenticationServices for the provider, and CryptoKit for keys and signatures. |
| `.github/workflows/ci.yml` | Builds the Mac app on `macos-latest`, unsigned. |
| `README.md`, `AGENTS.md` | Document the app, its install, and its rules, including which Apple frameworks it may use. |

## 3. Why this design

- **A credential provider extension is the only way in.** Safari and the system passkey sheet send requests only to an extension that the app registers. A browser extension that overrides `navigator.credentials` works only inside that browser, and it moves the private key into the browser's process.
- **CryptoKit instead of hand-written P-256.** Constant-time elliptic-curve scalar multiplication is far harder to get right than the symmetric code in `src/crypto`, and a subtle mistake leaks the private key through timing or bad signatures. CryptoKit ships with macOS, like the Rust standard library ships with Rust. Whether that keeps the "no dependencies" promise is question 1 in § 6.
- **One store implementation.** Linking the Rust code means the extension reads and writes the store exactly as the CLI does. A Swift port would be a second implementation of scrypt, the age format, and the store text to keep in agreement.
- **The store stays symmetric.** Passkeys are public-key cryptography, and a large enough quantum computer could forge one from the public key that the site holds. That is true whichever provider keeps the private key. multipass still encrypts its store only with a passphrase, so holding passkeys adds no public-key step to the store itself.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| On webauthn.io in Safari, register with multipass as the provider | The system sheet offers multipass. After the passphrase, `multipass list` shows a new entry marked as holding a passkey. |
| Sign out, then sign back in with that passkey | The sign-in succeeds after the passphrase |
| Enter a wrong passphrase in the extension | The sign-in is cancelled, and the store is unchanged |
| `age -d` on the store | Shows `multipass 3` and the entry's `passkey` line |
| `multipass rm` the entry, then try the sign-in again | multipass offers no passkey for the site |

Tests: format 3 round-trips through `to_text` and `from_text`, and a literal format 2 store still opens. The C interface rejects a null or unterminated string. The extension's signature verifies under the public key it registered, checked with CryptoKit in a Swift unit test.

## 5. Cost

Each sign-in decrypts the store once, about 300 ms at work factor 18, and one P-256 signature is too small to notice. The app adds an Xcode build to CI, likely a few minutes on each push.

## 6. Open questions

Each of these blocks the design:

1. **Apple frameworks and "no dependencies".** Sign with CryptoKit, or hand-write P-256 to keep the code fully in this repository? Recommended: CryptoKit, treated like the standard library. Owner: the user.
2. **Platforms.** The Mac only, or the Mac and iPhone? An iPhone needs its own app and extension, and the store syncing through iCloud Drive. Recommended: the Mac first, the iPhone as its own project. Owner: the user.
3. **Distribution.** Developer ID with notarization, or the Mac App Store? Both need a paid Apple Developer membership. Recommended: Developer ID, which needs no app review. Owner: the user.
4. **Unlocking in the extension.** Type the passphrase at every sign-in, or keep the store key in the Keychain behind Touch ID? Recommended: the passphrase at first, Touch ID later. Owner: the user.
5. **Reaching the store from the sandbox.** The extension runs sandboxed and cannot read `~/.multipass/store.age`. Either the store moves to the app's App Group container and the CLI follows it, or the app keeps a security-scoped bookmark that the extension resolves. Owner: the implementer, through the prototype in § 7, before this plan goes `ready`.

## 7. Background

- Apple opened passkey providers to third-party apps in iOS 17 and macOS 14 (Sonoma), with new methods on `ASCredentialProviderViewController` (Matt Miller, "WWDC23 passkeys", blog.millerti.me, 2023-06-10).
- Not yet verified, so a prototype comes first: whether the provider entitlement works under Developer ID signing (a GitHub discussion says it does; Apple's documentation does not say), and whether Chrome on macOS offers third-party providers. One developer reports that macOS shows third-party providers to sites as "iCloud Keychain" by zeroing the AAGUID.
- The FIDO Alliance's Credential Exchange Format, v1.0 with errata dated 2026-03-09, and its Credential Exchange Protocol define how to move passkeys between providers. 1Password helped write them. Importing your existing passkeys from 1Password would use them, and that belongs in a later project.
