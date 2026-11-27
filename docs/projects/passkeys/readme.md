---
status: draft
priority: now
---

# Passkeys

multipass holds passkeys in its store and signs you in with them on your Mac and iPhone, through a small app that each system lists as a passkey provider, with the store synced between them through iCloud Drive.

## 1. Problem

A passkey is a WebAuthn credential: a P-256 key pair that a site creates for you, where the site keeps the public key and you keep the private key. To sign in, the browser asks the operating system for a signature. The system hands the request to a passkey provider, such as iCloud Keychain or 1Password, which finds the matching private key and signs.

multipass cannot be that provider. It is a command-line tool, and macOS and iOS send passkey requests only to an AutoFill credential provider extension inside a signed app (`ASCredentialProviderViewController`, macOS 14 and iOS 17 and later). It also runs only on the Mac, so the store never reaches your iPhone. It also stores only text fields, with nowhere to keep a private key, a credential ID, and the site it belongs to. So every passkey you create today lives in iCloud Keychain or 1Password. Passkeys are replacing passwords on more sites each year, so a multipass that cannot hold them guards a shrinking share of your accounts.

## 2. Solution

A new app, `Multipass.app`, built for both iOS and macOS from one Xcode project, exists only to host a credential provider extension on each system. The extension links the existing Rust store code as a static library, so the store keeps one implementation. The store moves into the app's iCloud Drive folder, so the iPhone, the Mac app, and the CLI share one file. It signs with Apple's CryptoKit, so multipass never implements elliptic-curve arithmetic itself. You unlock it with Face ID or Touch ID: the first sign-in on each device asks for the passphrase once, and the extension keeps it in that device's Keychain where only your face or fingerprint can read it. A passkey becomes a `passkey` field on an entry, beside the secret, username, notes, and one-time password, in store format 3. The CLI lists and removes passkeys. Only the extension creates them and signs with them, because only the extension receives the site's request.

This design depends on the answers to § 6. Until those are settled, this plan stays a draft.

### 2.1 How a sign-in works

1. A site calls `navigator.credentials.get()`. macOS or iOS shows its passkey sheet, which offers multipass among the providers.
2. You choose multipass. The system starts the extension and calls `prepareInterface(forPasskeyRegistration:)` for a new passkey, or its assertion counterpart for a sign-in.
3. The extension asks for Face ID or Touch ID and reads the passphrase from its Keychain item (§ 2.3). When there is no item, or the passphrase in it no longer opens the store, it shows its own passphrase field instead, and saves what you type to a new item. It then decrypts the store through the Rust library, which takes about 300 ms.
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

### 2.3 The Keychain item

The item holds the passphrase itself, not a key derived from it. Every save re-encrypts the store with a fresh scrypt salt, and a registration saves, so the extension needs the passphrase and not just the key for one version of the file.

| Attribute | Value | Why |
| --- | --- | --- |
| Class | Generic password, in a Keychain access group that the app and the extension share | The app's settings can remove it, and the extension reads it |
| Access control | `biometryCurrentSet` | Only a Face ID or Touch ID match reads it, and enrolling a new face or fingerprint makes it unreadable |
| Accessibility | `whenPasscodeSetThisDeviceOnly` | It never syncs to iCloud Keychain or leaves the device, and it disappears if the device's passcode is removed. Each device keeps its own item. |

After you change the passphrase with `multipass passwd`, the old item no longer opens the store. The next sign-in falls back to the passphrase field and replaces the item. The CLI never reads or writes the item; it still asks for the passphrase every time.

### 2.4 Syncing through iCloud Drive

The store lives at `Documents/store.age` in the app's iCloud container, which iCloud Drive copies between your devices. The file is ciphertext, so iCloud holds nothing readable.

| Reader | How it reaches the store |
| --- | --- |
| The app and its extension, on both systems | Through the iCloud container, with `NSFileCoordinator` around each read and save |
| The CLI on the Mac | Through `MULTIPASS_STORE`, set to the container's path under `~/Library/Mobile Documents/`. The app's settings show the exact path and the `export` line to copy. |

multipass does not merge. When two devices save before iCloud syncs, iCloud keeps both versions as a conflict. The app and its extension both check for unresolved conflict versions before each save, and refuse to save while any exist. The extension saves on every registration, so it checks too: it cancels the registration and tells you to open the app, and the app shows which devices wrote the versions. So a passkey registration never silently replaces another device's change. You resolve the conflict in the app by choosing a version. The CLI does not see conflict versions, so the README tells you to edit from the CLI only while no other device is saving.

### 2.5 Changes by file

| Path | Change |
| --- | --- |
| `Cargo.toml` | Adds a `[lib]` target with `crate-type = ["staticlib", "rlib"]`, so the extension can link the store code. Still no dependencies. |
| `scripts/build-xcframework.sh` | New. Builds the static library for macOS, iOS, and the iOS simulator, and bundles the three into one XCFramework for Xcode. |
| `src/crypto/base64.rs` | `encode` and `decode` stop branching on the data and indexing memory with it, because the `passkey` field's `key` is a private key. Each 6-bit value maps to its character, and each character to its value and an invalid flag, with masked arithmetic in place of `ALPHABET` and the `match` in `value`. Every rejection, the stray-bits check included, folds into that flag, and `decode` branches on it once, after the last character. The RFC 4648 tests stay and must still pass. |
| `src/ffi.rs` | New. A C interface over `Store`: open with a passphrase, find a passkey, add an entry, save, and free. |
| `src/store.rs` | Format 3: the `passkey` field, and reading formats 1 to 3. |
| `src/main.rs` | `list` marks entries that hold a passkey; `get --field passkey` prints the site and creation date, never the key. |
| `apple/` | New. One Xcode project, in Swift, that builds the app and its extension for iOS and macOS from shared sources, as a SwiftUI multiplatform app: shared SwiftUI views, with a thin per-platform `ASCredentialProviderViewController` subclass in each extension. It uses only Apple's frameworks: AuthenticationServices for the provider, CryptoKit for keys and signatures, LocalAuthentication and Security for Face ID, Touch ID, and the Keychain item, and Foundation's file coordination for iCloud Drive. The app's settings show the store's path, resolve sync conflicts, and remove the Keychain item. |
| `.github/workflows/ci.yml` | Builds the XCFramework and both apps on `macos-latest`, unsigned. |
| `AGENTS.md` | Documents the app's build, and changes three rules the design would otherwise break. The dependency rule allows Apple's system frameworks like the Rust standard library, and third-party code stays banned on every platform, including Swift packages. "Every primitive lives in `src/crypto`" exempts the primitives Apple's frameworks provide to `apple/`, CryptoKit's P-256 key generation and `P256.Signing`, and only those. "Passphrases come from `/dev/tty` through `tty::read_hidden`" adds the extension's two sources, its own passphrase field and the per-device Keychain item that only Face ID or Touch ID reads (§ 2.3), and the CLI keeps `/dev/tty` as its only source. The ban on passphrases in argv, environment variables, logs, and errors stays and covers the extension. |
| `README.md` | Documents the app, its install through TestFlight, and Face ID or Touch ID unlock. Corrects three claims the design makes untrue. "Every line of multipass, cryptography included, is in this repository" becomes true of everything but the P-256 keys and signatures CryptoKit computes. "What is left to trust is the Rust toolchain and its standard library" adds, for the app and its extension, Xcode's Swift toolchain and Apple's system frameworks. "Passphrases come from a hidden terminal prompt" becomes true of the CLI, while the extension takes them from its own field or its Keychain item. |

## 3. Why this design

- **A credential provider extension is the only way in.** Safari and the system passkey sheet send requests only to an extension that the app registers. A browser extension that overrides `navigator.credentials` works only inside that browser, and it moves the private key into the browser's process.
- **CryptoKit instead of hand-written P-256.** Constant-time elliptic-curve scalar multiplication is far harder to get right than the symmetric code in `src/crypto`, and a subtle mistake leaks the private key through timing or bad signatures. CryptoKit ships with macOS and iOS, as the Rust standard library ships with Rust. So the "no dependencies" rule treats Apple's system frameworks like the standard library: allowed, while third-party code stays banned.
- **Face ID and Touch ID from the start.** A passkey sign-in is meant to take a second, and typing a long passphrase each time defeats that, on a phone most of all. The cost is a second way into the store: anyone who passes Face ID or Touch ID on one of your devices can read the passphrase. `biometryCurrentSet` and `ThisDeviceOnly` limit that way in to your enrolled face or fingers on each device.
- **The Mac and iPhone together, through iCloud Drive.** A passkey that exists on only one device fails you on the other, so both ship at once. iCloud Drive is already on both devices and moves only ciphertext. A sync service of multipass's own would mean a server, which multipass refuses to run.
- **One store implementation.** Linking the Rust code means the extension reads and writes the store exactly as the CLI does. A Swift port would be a second implementation of scrypt, the age format, and the store text to keep in agreement.
- **The store stays symmetric.** Passkeys are public-key cryptography, and a large enough quantum computer could forge one from the public key that the site holds. That is true whichever provider keeps the private key. multipass still encrypts its store only with a passphrase, so holding passkeys adds no public-key step to the store itself.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| On webauthn.io in Safari, register with multipass as the provider | The system sheet offers multipass. The extension asks for the passphrase once, and `multipass list` then shows a new entry marked as holding a passkey. |
| Sign out, then sign back in with that passkey | The extension asks only for Touch ID, and the sign-in succeeds |
| Cancel the Touch ID prompt | The sign-in is cancelled, and the store is unchanged |
| Run `multipass passwd`, then sign in again | The extension falls back to the passphrase field, and the following sign-in asks only for Touch ID again |
| Enter a wrong passphrase in the fallback field | The sign-in is cancelled, the store is unchanged, and no Keychain item is saved |
| Remove the item from the app's settings, then sign in | The extension asks for the passphrase again |
| `age -d` on the store | Shows `multipass 3` and the entry's `passkey` line |
| `multipass rm` the entry, then try the sign-in again | multipass offers no passkey for the site |
| Register a passkey in Safari on the iPhone, wait for iCloud Drive to sync, then sign in on the Mac | The Mac's extension finds the passkey and signs in |
| Register on both devices while one is offline, then bring it online | The app reports a conflict and saves nothing until you choose a version. Neither registration is lost. |

Tests: format 3 round-trips through `to_text` and `from_text`, and a literal format 2 store still opens. The C interface rejects a null or unterminated string. The extension's signature verifies under the public key it registered, checked with CryptoKit in a Swift unit test that runs on both platforms. The library's random bytes come from the system on iOS as well as macOS, checked by the same test that checks them on the Mac. Installing a build on a phone for these checks waits for the user to ask.

## 5. Cost

Each sign-in decrypts the store once after the Face ID or Touch ID prompt. That takes about 300 ms at work factor 18 on an Apple-silicon Mac; scrypt's 256 MiB of memory is the cost to measure on the iPhone, inside an extension's memory limit, in the prototype. One P-256 signature is too small to notice. iCloud Drive usually syncs within seconds to minutes, so a passkey registered on one device may not be on the other right away. The two app builds and the XCFramework add several minutes to CI on each push.

## 6. Open questions

Question 5 blocks the plan until the prototype in § 8 answers it, and questions 7 to 9 wait on the user. Questions 1 to 4 and 6 are decided.

1. **Apple frameworks and "no dependencies".** Decided: sign with CryptoKit. Apple's system frameworks count like the Rust standard library, and third-party code stays banned.
2. **Platforms.** Decided: the Mac and iPhone together, with the store synced through iCloud Drive as § 2.4 describes.
3. **Distribution.** Decided: TestFlight on both the Mac and the iPhone, under one App Store Connect record, so every device updates the same way. The App Store can follow later, if the app is opened to others.
4. **Unlocking in the extension.** Decided: Touch ID from the start, with the passphrase kept in the Keychain as § 2.3 describes.
5. **Reaching the iCloud container from the extension.** § 2.4 has the extension read the store from the app's iCloud container. Whether an AutoFill extension may open that container directly, or needs the app to keep a copy in a shared App Group container, is unverified. Owner: the implementer, through a prototype, before this plan goes `ready`.
6. **How one project builds both apps.** Decided: a SwiftUI multiplatform app. If the prototype shows that Mac Catalyst would share more of the extension's code, the implementer switches to Catalyst and records why here. The unmodified iPad build on the Mac ("Designed for iPad") is ruled out, because it runs only on Apple-silicon Macs and may not run the extension.
7. **Naming a new passkey's entry.** When a site registers a passkey, the extension must choose an entry. Recommended: use the site's relying party ID, such as `github.com`, as the name. When an entry with that name exists, add the `passkey` field to it, grouped with its password and one-time password as `otp` is. Owner: the user.
8. **One passkey per entry, or several.** A second account on the same site registers a second passkey for the same relying party ID. Recommended: one passkey per entry, with the second account's entry named `<rp id> <user name>`, such as `github.com octocat-work`, so each entry still describes one account. Owner: the user.
9. **Removing a passkey without its entry.** `rm` deletes a whole entry, including its password. Recommended: `multipass passkey <name> --clear`, which mirrors `otp --clear`. An entry must then hold at least one of `secret`, `otp`, and `passkey`, so `--clear` fails when it would leave the entry empty. Owner: the user.

## 7. Background

- Apple opened passkey providers to third-party apps in iOS 17 and macOS 14 (Sonoma), with new methods on `ASCredentialProviderViewController` (Matt Miller, "WWDC23 passkeys", blog.millerti.me, 2023-06-10).
- The Rust standard library supports `aarch64-apple-ios` and `aarch64-apple-ios-sim` as well as the Mac targets, so the same zero-dependency code builds for the iPhone.
- Not yet verified, so the prototype checks it: whether Chrome on macOS offers third-party providers. Safari does. One developer reports that macOS shows third-party providers to sites as "iCloud Keychain" by zeroing the AAGUID.
- The FIDO Alliance's Credential Exchange Format, v1.0 with errata dated 2026-03-09, and its Credential Exchange Protocol define how to move passkeys between providers. 1Password helped write them. Importing your existing passkeys from 1Password would use them, and that belongs in a later project.

## 8. Rollout

These steps run in order. Steps 2 and 4 need the user's Apple developer account and devices.

1. **Prototype.** Build a bare extension that registers and signs with a fixed test key on both platforms, and answer question 5: can the extension open the app's iCloud container directly? Also measure scrypt at work factor 18 inside the iPhone extension's memory limit, and check whether Chrome on the Mac offers the extension. Record the results in § 7, and move this plan to `ready`.
2. **Apple setup.** The user creates the App Store Connect record and the identifiers the app needs: the bundle IDs for the app and its extensions, the App Group, the iCloud container, and the Keychain access group. App Store Connect also asks whether the app uses encryption. It does, both its own and Apple's, so the user answers the export compliance questions for an app that encrypts only the user's own data.
3. **Build.** Implement § 2 and pass the tests in § 4, on CI and locally.
4. **TestFlight.** Upload builds for both platforms. The user installs them from TestFlight on the Mac and the iPhone, and runs the checks in § 4's table.
