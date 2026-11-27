---
status: in-progress
priority: now
---

# Installer and releases

One command installs multipass on a Mac, and it installs only code it can show came from a tagged release: it builds the tagged source when Rust is installed, and otherwise checks a prebuilt binary's GitHub attestation before it installs it.

## 1. Problem

Today the only way to install multipass is to clone the repository and run `cargo install --path .`, as the README's Install section says. That asks every user to have Git and Rust and to know Cargo. There are no releases either: no tag, no version anyone can name, and no way to tell whether the `multipass` on your PATH is current.

The usual fix, a `curl … | bash` installer that downloads a binary, is itself a supply-chain risk, and supply-chain attacks are what multipass exists to avoid. Its README promises that the only code you trust beyond this repository is the Rust toolchain and its standard library, and CI fails if a single crate appears. A prebuilt binary breaks that promise unless something proves the binary was built from this repository's source. A checksum downloaded from the same place as the binary proves nothing on its own: whoever can replace the binary can replace the checksum beside it.

## 2. Solution

A new `install.sh` at the repository root installs a release into `~/.local/bin/multipass`. When `cargo` is on PATH, it downloads the release's source archive and builds it with `cargo build --release --locked --offline`, which takes about three seconds because multipass has no dependencies, so the only code it trusts beyond the tagged source is your own toolchain. Without `cargo`, it downloads the release's universal macOS binary and installs it only after `gh attestation verify` proves that the release workflow built it from the release's tag. When neither `cargo` nor `gh` is installed, it refuses and says how to get either one, unless you set `MULTIPASS_UNVERIFIED=1`. Run from a checkout, it builds that checkout instead and downloads nothing. A new release workflow publishes each version you merge: it tags `v<version>` from `Cargo.toml`, builds the binary on a pinned toolchain, attests it, and publishes an immutable GitHub release. The build is reproducible, and `install.sh verify` rebuilds a release on your Mac and compares the bytes. The installer never touches your stores, `~/.multipass`, or your shell's startup files.

The installer itself is a release asset, attested with the binary. The project's domain, `getmultipass.dev`, serves no code: a small Vercel website, built from `site/` and deployed by a GitHub Actions workflow on every push to `main`, redirects `https://getmultipass.dev/install.sh` to the newest release's `install.sh` on GitHub (§ 2.9). So the command you run is:

```sh
curl -fsSL https://getmultipass.dev/install.sh | bash
```

### 2.1 How an install runs

1. The installer finds its source. A script whose directory holds a `Cargo.toml` with `name = "multipass"` is in a checkout, and installs that checkout: it skips steps 2 to 5, builds the checkout as step 4.3 does, and stops with status 69 when `cargo` is missing. A checkout can change without a version bump, so instead of step 3 a rerun always builds, and prints `current` and leaves the file alone when the new binary's SHA-256 matches the receipt. The build is reproducible, so an unchanged checkout always matches. Anything else, such as a script piped from `curl`, installs a release.
2. It picks the release: `MULTIPASS_VERSION` when set, or else the newest release, which it reads without the GitHub API from where `https://github.com/ninjudd/multipass/releases/latest` redirects. It prints `release        ninjudd/multipass v0.2.0`.
3. When the receipt (§ 2.4) records that version, and the installed binary's SHA-256 still matches the receipt, it prints `current        ~/.local/bin/multipass 0.2.0` and exits 0 without downloading anything else.
4. With `cargo` on PATH, or `MULTIPASS_BUILD=source`, it builds from source:
   1. It downloads `https://github.com/ninjudd/multipass/archive/refs/tags/v0.2.0.tar.gz` into a temporary directory and prints `fetched        v0.2.0 source, sha256 <digest>`.
   2. It checks that `Cargo.toml` says `version = "0.2.0"`, and that `Cargo.lock` lists one package, multipass itself.
   3. It runs `cargo build --release --locked --offline` with `CARGO_TARGET_DIR` inside the temporary directory, and prints `built          v0.2.0 with rustc 1.97.1`. `--offline` proves that the build fetched nothing, and `--locked` that the lock file matched.
5. Otherwise, or with `MULTIPASS_BUILD=binary`, it installs the prebuilt binary:
   1. On anything but macOS it stops with exit status 69: `install.sh: there is no prebuilt multipass for Linux; install Rust from https://rustup.rs and run the installer again`.
   2. It downloads `multipass-0.2.0-macos`, `multipass.sigstore.json`, and `SHA256SUMS` from the release.
   3. It checks the binary against `SHA256SUMS` and prints `checksum       matches SHA256SUMS`. That catches a truncated or corrupted download, and nothing more.
   4. With `gh` on PATH, it reads the commit the tag names from `https://api.github.com/repos/ninjudd/multipass/commits/v0.2.0`, sent with `Accept: application/vnd.github.sha`, which needs no login. It then runs `gh attestation verify multipass-0.2.0-macos --bundle multipass.sigstore.json --repo ninjudd/multipass --signer-workflow ninjudd/multipass/.github/workflows/release.yml --source-ref refs/heads/main --source-digest <commit> --deny-self-hosted-runners`. The release workflow runs on the merge to `main` and tags that same commit afterwards, so the attestation's certificate records `refs/heads/main` and the commit, never the tag (§ 8). `--source-digest` is what ties the binary to the tag, and `--source-ref` rejects a run started from any other branch. With `--bundle`, `gh` needs no login (§ 8). It prints `attested       built by release.yml on main at <short sha>, the commit v0.2.0 names`, or stops with status 65 and `gh`'s reason, installing nothing. When the API cannot answer, as when its limit of 60 requests an hour for one address is spent, it stops with status 69, says why, and installs nothing.
   5. Without `gh`, it stops with status 69, before it downloads anything: `install.sh: cannot prove this binary was built from v0.2.0 -- install Rust (https://rustup.rs) to build it from source, or gh (https://cli.github.com) to check its attestation; MULTIPASS_UNVERIFIED=1 installs it unchecked`. With `MULTIPASS_UNVERIFIED=1` it goes on and prints a warning row, `unverified     ⚠️  installed without checking where the binary came from`.
6. It runs the candidate with `--version` and stops with status 65 unless it prints `multipass 0.2.0`.
7. It copies the candidate to `$BIN_DIR/.multipass.<pid>`, sets mode 0755, renames it over `$BIN_DIR/multipass`, writes the receipt, and prints `installed      ~/.local/bin/multipass 0.2.0 (built from source)`. The rename means a running `multipass` keeps its old file and never sees a half-written one.
8. It checks PATH. When `$BIN_DIR` is not on it, it prints a warning row with the line to add, such as `not-on-path    ⚠️  add export PATH="$HOME/.local/bin:$PATH" to your shell's startup file`. When `command -v multipass` names another file, it prints `shadowed       ⚠️  /usr/local/bin/multipass comes first on PATH`, because Canonical's Multipass, a tool for Ubuntu virtual machines, installs a command of the same name there. It lists every other `multipass` on PATH, such as one from `cargo install`, as `other          ~/.cargo/bin/multipass`.
9. It removes the temporary directory, on success or failure.

Each row is a fixed-width name and a message, as in Projector's installer, and a warning row is bold yellow on a terminal and always carries the marker, so a captured log shows it too. Every failure names the step, the file or URL, and what to do. The script defines every step as a function and calls `main "$@"` on its last line, so a `curl | bash` download cut short defines functions and runs nothing.

### 2.2 Commands and settings

| Command | What it does |
| --- | --- |
| `install.sh` or `install.sh install` | Installs or upgrades, as § 2.1 describes. |
| `install.sh status` | Prints the newest release, what is installed and how, and whether it is `current`, `stale` (with the command to upgrade), or `modified` (the file no longer matches the receipt). Run from a checkout, it compares with the checkout's version instead of the newest release, and reads nothing from the network. Adds the PATH rows from step 8. Changes nothing. |
| `install.sh verify [<version>]` | Rebuilds a release with the toolchain its build info names and compares the bytes, as § 2.6 describes. Installs nothing. |
| `install.sh uninstall` | Removes `$BIN_DIR/multipass` when its SHA-256 matches the receipt, then the receipt. A file that does not match is left in place with a `user-owned` row. Ends with `kept           your stores, such as ~/.multipass/store.age`. |

From `curl`, pass a command after `-s --`: `curl -fsSL <url> | bash -s -- status`.

| Variable | Default | Effect |
| --- | --- | --- |
| `MULTIPASS_VERSION` | the newest release | The release to install, such as `0.2.0`. |
| `MULTIPASS_BUILD` | `source` when `cargo` is on PATH, else `binary` | Forces one way to install. |
| `MULTIPASS_BIN_DIR` | `~/.local/bin` | Where `multipass` goes. |
| `MULTIPASS_UNVERIFIED` | unset | `1` installs a prebuilt binary without `gh`. |
| `MULTIPASS_REPO` | `ninjudd/multipass` | The GitHub repository to install from, for a fork's releases. The attestation check names this repository. |
| `MULTIPASS_DOWNLOAD_URL` | `https://github.com/<repo>/releases/download` | Where release assets come from, such as a `file://` mirror in a test. The attestation check still names `MULTIPASS_REPO`, so a mirror cannot change what passes. |
| `MULTIPASS_ARCHIVE_URL` | `https://github.com/<repo>/archive/refs/tags` | Where source archives come from, as `<url>/v<version>.tar.gz`, so `tests/install.sh` can install a release from source through a `file://` mirror before any release exists. A build from source trusts the archive it downloads, so a mirror is trusted as GitHub is. |
| `MULTIPASS_OFFLINE` | unset | `1` makes `status` skip reading the newest release. |

The receipt lives under `XDG_DATA_HOME`, so `status` and `uninstall` follow it there. None of these names collides with `MULTIPASS_STORE`, which the CLI reads.

### 2.3 Upgrading

You upgrade with `multipass upgrade`, which runs the installer for you, or by running the installer again yourself (§ 7.2). multipass contains no network code, and it reaches the network only when you type `upgrade`: there are no background checks and no new-version notices.

`multipass upgrade [<version>]` runs these steps:

1. It reads the receipt (§ 2.4). When the receipt is missing, or names a file other than the running executable, it stops with status 69: `multipass: this multipass was not installed by the installer (it is <path>); upgrade it the way you installed it, or run the installer`. When the receipt's `method` is `checkout`, it stops with status 69 and says to pull the checkout and run `./install.sh` there. So `upgrade` never writes a second copy that the first one then shadows.
2. In a new 0700 temporary directory, it runs `/usr/bin/curl -fsSL -o install.sh https://getmultipass.dev/install.sh`, or `https://getmultipass.dev/v<version>/install.sh` when you name a version. `curl` is an external program at a fixed path, as `/bin/stty` is for the passphrase prompt, so multipass gains no dependency and no network code of its own.
3. With `gh` on PATH, it downloads the release's bundle beside the script, from `https://github.com/ninjudd/multipass/releases/latest/download/multipass.sigstore.json`, or `releases/download/v<version>/` when you name a version. It runs `gh attestation verify install.sh --bundle multipass.sigstore.json --repo ninjudd/multipass --signer-workflow ninjudd/multipass/.github/workflows/release.yml --source-ref refs/heads/main --deny-self-hosted-runners`, which needs no login, and stops with status 65, running nothing, when that fails. A release published between the two downloads makes the check fail rather than pass, and running `upgrade` again fixes it. The installer then checks the binary against the commit its tag names, as § 2.1 step 5.4 describes. Without `gh`, it says `multipass: running the installer unchecked, as curl | bash would`. Downloading to a file first is what makes this check possible, which piping into `bash` would not allow.
4. It runs `/bin/bash install.sh`, with `MULTIPASS_VERSION` set when you named a version, and `MULTIPASS_BIN_DIR` set to the receipt's directory, and passes the installer's rows and exit status through. The installer then builds from source or checks the binary's attestation, exactly as § 2.1 describes.
5. It removes the temporary directory.

The version is an argument rather than an option, because `--version` already prints multipass's own version. It may carry a leading `v`, and anything but a release version such as `0.2.0` or `1.0.0-rc.1` is refused before any download, so a version never puts anything else into a URL. `upgrade` takes no other option, `--store` included, since it opens no store. A signal that ends the installer makes `upgrade` exit 1.

`multipass upgrade --check` runs `/usr/bin/curl -fsSI https://github.com/ninjudd/multipass/releases/latest`, reads the newest release's tag from the redirect, compares it with its own version, and changes nothing. It prints `multipass 0.2.0 is the newest release` and exits 0, or `multipass 0.3.0 is out, and this is 0.2.0 -- run multipass upgrade` and exits 1, so a script can test it. A build newer than the newest release, such as one from a checkout ahead of it, prints `multipass 0.3.0 is newer than the newest release, 0.2.0` and exits 0.

`upgrade` never asks for the passphrase and opens no store. It passes its own environment through to the installer, which needs `PATH` and `HOME`, and adds only the two variables above. A running session-unlock agent ends on its own after an upgrade (§ 2.7).

### 2.4 The receipt

The installer records what it installed in `${XDG_DATA_HOME:-$HOME/.local/share}/multipass-install/receipt`, as `key value` lines. It is the only file the installer writes outside `$BIN_DIR`.

| Key | Value |
| --- | --- |
| `version` | `0.2.0` |
| `method` | `source`, `binary`, `unverified`, or `checkout` |
| `path` | The installed file, such as `/Users/you/.local/bin/multipass` |
| `sha256` | The installed file's SHA-256 |
| `source` | `ninjudd/multipass v0.2.0`, or a checkout's path |
| `installed` | The time, in UTC, as `2026-12-01T10:00:00Z` |

### 2.5 The release workflow

You release by merging a pull request that raises `version` in `Cargo.toml` and `Cargo.lock`. The merge is the decision to ship, and the workflow derives everything else from that version, so the tag and the code cannot disagree.

`.github/workflows/release.yml` runs on a push to `main` that changes `Cargo.toml`, and on `workflow_dispatch`, which publishes the current version if it has no release yet, for the first release and for a run that failed. Its top-level permissions are empty, and it runs one release at a time.

1. **`build`**, on a pinned macOS runner image, with `contents: read` and no other permission:
   1. Fails unless the run's ref is `refs/heads/main`, because the attestation records the ref the run started from and the installer accepts only `main`, so a dispatch from another branch could never publish a binary anyone installs. Checks out the pushed commit with `persist-credentials: false`, and reads the version from `Cargo.toml`. When a published release `v<version>` already exists, it sets an output that skips `publish` and stops.
   2. Installs the Rust version pinned in the workflow's `RUST_VERSION` with `rustup toolchain install --profile minimal --target aarch64-apple-darwin,x86_64-apple-darwin`. The runner image already has rustup, so the workflow uses no third-party action.
   3. Runs `.github/scripts/build-release.sh`, which unpacks `git archive HEAD` (the same files as GitHub's source archive for the tag) at two paths of different lengths and builds both targets in each with `cargo build --release --locked --offline`, `MACOSX_DEPLOYMENT_TARGET=11.0`, `RUSTFLAGS="-C link-arg=-Wl,-oso_prefix,."`, and `CARGO_TARGET_DIR` inside the unpacked source. It fails when any byte differs, so a change that makes the build depend on its path or the time cannot ship. The flag is why the paths do not matter (§ 8). The script runs the same way on a Mac, so a change to the release build can be tried before it merges.
   4. Joins the two with `lipo -create` into `multipass-<version>-macos`, and fails unless it prints `multipass <version>` for `--version`.
   5. Writes `SHA256SUMS` and `multipass-<version>.buildinfo` (§ 2.6), copies `install.sh`, and uploads the four files as a workflow artifact.
2. **`publish`**, needing `build`, with `contents: write`, `id-token: write`, and `attestations: write`. It never checks out the repository, so no code from the repository runs while it holds those permissions.
   1. Downloads the artifact.
   2. Runs `actions/attest-build-provenance` on the binary and `install.sh`, and saves the bundle it writes as `multipass.sigstore.json`. The name carries no version, so `releases/latest/download/multipass.sigstore.json` always names the newest release's bundle.
   3. Deletes a draft `v<version>` left by a failed run, creates the release as a draft with `gh release create v<version> --target <commit> --generate-notes` and the five files, then publishes it. GitHub's immutable releases lock the tag and the assets once it is published.

Every action the workflow uses is GitHub's own and is pinned by full commit SHA: `actions/checkout`, `actions/upload-artifact`, `actions/download-artifact`, and `actions/attest-build-provenance`. The workflow uses no secret, only the job token. CI adds `--locked` to `cargo test`, so a version bump that forgets `Cargo.lock` fails in its pull request rather than in the release.

| Release asset | What it is |
| --- | --- |
| `multipass-<version>-macos` | The universal binary, arm64 and x86_64, ad-hoc signed by the linker as Apple silicon requires |
| `install.sh` | The installer at the release's tag |
| `multipass.sigstore.json` | The Sigstore bundle of the build attestation, covering the binary and `install.sh` |
| `SHA256SUMS` | The SHA-256 of the binary and `install.sh` |
| `multipass-<version>.buildinfo` | What the build ran on, as § 2.6 lists |

### 2.6 Checking a release yourself

A release is reproducible: anyone with the same Rust toolchain and macOS SDK gets the same bytes from the same tag. The build info records what it takes, as `key value` lines; `rustc -vV` becomes one `rustc-<field>` line per field, such as `rustc-release 1.97.1`.

| Field | Example |
| --- | --- |
| `tag`, `commit` | `v0.2.0`, the full commit SHA |
| `rustc` | The full `rustc -vV` output, including the commit hash of rustup's toolchain |
| `xcode`, `sdk` | `xcodebuild -version` and `xcrun --show-sdk-version` |
| `macosx_deployment_target` | `11.0` |
| `rustflags` | `-C link-arg=-Wl,-oso_prefix,.`, which `install.sh verify` builds with |
| `command` | The exact `cargo build` command |
| `sha256` | Each slice's digest and the universal binary's |

`install.sh verify 0.2.0` downloads the source, the binary, and the build info, builds your Mac's slice with `cargo +<version> build --release --locked --offline --target <triple>`, extracts the same slice with `lipo -thin`, and compares them. It prints `reproduced     v0.2.0 arm64 slice matches the release`, or `differs` with each build-info field that differs on your Mac, such as the SDK version, and exits 65. It needs rustup, because a toolchain from Homebrew embeds its own install path in the binary, and it stops with status 69 and the `rustup toolchain install` command when the toolchain the release names is missing, rather than installing one itself. It builds with the build info's `rustflags` and `macosx_deployment_target`, inside the unpacked source as the release build does.

To check the installer before you run it, download it and verify it the same way:

```sh
curl -fsSLO https://getmultipass.dev/install.sh
curl -fsSLO https://github.com/ninjudd/multipass/releases/latest/download/multipass.sigstore.json
gh attestation verify install.sh --bundle multipass.sigstore.json --repo ninjudd/multipass \
  --signer-workflow ninjudd/multipass/.github/workflows/release.yml --source-ref refs/heads/main
bash install.sh
```

The bundle makes the check work without a `gh` login.

To pin a release, so a later release cannot change what you run, name its tag in the URL and its version for the installer. GitHub's own URL for the same file skips the domain entirely:

```sh
curl -fsSL https://getmultipass.dev/v0.2.0/install.sh | MULTIPASS_VERSION=0.2.0 bash
curl -fsSL https://github.com/ninjudd/multipass/releases/download/v0.2.0/install.sh | MULTIPASS_VERSION=0.2.0 bash
```

### 2.7 Other plans

- **Session unlock** starts an agent, `multipass __agent`, from the same binary, and the client checks that the agent runs the same executable by its path. After an upgrade, the path names the new file while an agent started earlier still runs the old one, so a path check passes for a different program. The session-unlock plan covers this in its § 2.5, in the "Same binary" row: the agent records its executable's device, inode, size, and change time when it starts, checks them again on each request, and ends the session with `multipass was updated` when any of them changes, and the client refuses an agent whose executable differs from its own on the same values. So the next command after an upgrade asks for the passphrase and starts an agent from the new binary. That covers `multipass upgrade`, a rerun of the installer, `cargo install`, and a copy by hand alike, so neither the installer nor `upgrade` adds anything for it.
- **Vault key and the mergeable store** change the store. The mergeable store writes format 3 in the same file, and an older multipass refuses it with its existing message, `the store uses format 3, but this multipass reads formats 1 and 2`. The vault key then moves the store into a package, `~/.multipass/store.multipass`, and keeps `store.age` until it has gone 30 days unchanged, merging any change made to it. For up to those 30 days, a multipass from before the vault key still reads and saves the old file, and the package merges its changes. Once the old file is retired, that multipass finds no file at its default path, so every command fails, and its `init` would create a new, empty `store.age` beside the package. The installer never opens a store, so it cannot tell, and installing an older release with `MULTIPASS_VERSION` stays possible. The warning not to go back to a release from before the vault key belongs to the vault-key plan's README row, because only that change moves a store, and the README describes only what is built.
- **Passkeys** adds `Multipass.app`, distributed through TestFlight, and session unlock's § 8 moves the agent into the app as a signed helper. If the app later ships the CLI too, it becomes a second way to install it, and `status` lists it as an `other` copy on PATH. Whether the installer should then defer to the app's copy is the passkeys plan's decision.

### 2.8 Changes by file

| File | Change |
| --- | --- |
| `install.sh` | New. The installer, with the commands and settings in § 2.2. Bash, using only `curl`, `tar`, `uname`, and `shasum -a 256`, or `sha256sum` where `shasum` is missing, as on minimal Linux systems without Perl, and, when present, `cargo`, `gh`, and `lipo`. |
| `.github/workflows/release.yml` | New. The release workflow in § 2.5. |
| `.github/scripts/build-release.sh` | New. The release build in § 2.5 step 1.3 to 1.5: both targets built twice and compared, joined with `lipo`, `SHA256SUMS`, and the build info. |
| `.github/workflows/ci.yml` | Adds `--locked` to `cargo test`, a step that runs `tests/install.sh`, and a step that runs `.github/scripts/check-site.sh static`, so a pull request that breaks the redirects fails before it can merge. |
| `tests/install.sh` | New. Runs the installer from the checkout with `HOME` in a temporary directory, and checks the rows, the receipt, a rerun, `status`, `uninstall`, and that nothing else under `HOME` changed. It also installs a release made from the checkout through a `file://` mirror: from source with `git archive` through `MULTIPASS_ARCHIVE_URL`, and, with neither `cargo` nor `gh` on `PATH`, the binary path through `MULTIPASS_DOWNLOAD_URL`, which must refuse, reject a binary that does not match `SHA256SUMS`, and install with `MULTIPASS_UNVERIFIED=1`. The attested path needs a real release, as § 4 says. |
| `README.md` | The Install section shows the one-line install, the check-first install and the pinned installs from § 2.6, the checkout install with `./install.sh`, how to upgrade and uninstall, and how to check a release with `install.sh verify`. The paragraph that says the only code you trust beyond the repository is the Rust toolchain and its standard library becomes true of each way to install: a build from source, whether by the installer or from a checkout, trusts the Rust toolchain and GitHub to serve the tagged source; a prebuilt binary also trusts GitHub's hosted macOS runner, with its Xcode linker and `lipo`, the pinned rustup toolchain, and GitHub's and Sigstore's signing of the attestation, which `gh attestation verify` checks and `install.sh verify` lets you replace with your own build; and the one-liner also trusts whoever controls `getmultipass.dev`, its registrar account, and its Vercel team, which the GitHub URL and the check-first install avoid. The one-liner, the check-first install, the pinned installs, and `install.sh verify` go into the README only at rollout step 7, once the first release and the domain exist; until then the README documents `./install.sh` from a checkout. The passkeys plan's README row changes the same paragraph for what its app adds, so whichever lands second keeps both changes. |
| `AGENTS.md` | A Releases section: how to cut a release, that `RUST_VERSION` in `release.yml` changes only in a pull request of its own, and that the release workflow uses only GitHub's actions, pinned by commit SHA. A Website section: that `site/` never holds a copy of `install.sh`, that `check-site.sh` guards its redirects, and that the Vercel CLI the site workflow installs is a deployment tool for the website, never a dependency of multipass, so the no-dependencies rule, which is about crates and the binary, does not cover it. |
| `site/index.html` | New. The landing page: what multipass is, the one-line install, the direct GitHub URL and the pinned and check-first installs from § 2.6, and links to the repository and the README. One static HTML file with inline CSS only, no scripts, and no third-party assets. |
| `site/vercel.json` | New. The redirects and headers in § 2.9, with no build command and no framework. |
| `.github/workflows/site.yml` | New. The deploy workflow in § 2.10. |
| `.github/vercel/package.json`, `.github/vercel/package-lock.json` | New. The Vercel CLI at one exact version, with every package it pulls in pinned by the lock file's integrity hashes. They sit outside `site/` so Vercel never reads `site/` as a Node project. |
| `tests/site/` | New. The bad `vercel.json` files that `check-site.sh static` must reject, one per case in § 4. |
| `.github/scripts/check-site.sh` | New. The redirect guard in § 2.10: `check-site.sh static` reads `site/vercel.json`, and `check-site.sh live <url>` reads the responses with `curl -sI`. |
| `src/upgrade.rs` | New. `upgrade` and `upgrade --check` as § 2.3 describes. It takes the paths of `curl`, `bash`, and `gh` and the base URL as parameters, so tests run it against fake programs in a temporary directory; `main.rs` passes the fixed paths and `https://getmultipass.dev`. |
| `src/main.rs` | Adds the `upgrade` command, its optional version, and `--check`, and updates `USAGE`. |

### 2.9 The domain

`getmultipass.dev` uses Vercel's DNS, under a Vercel team, and a Vercel project on that team serves the small website in `site/`: one static page and the redirects. The project has no build step, runs no code, holds no secret, and serves no copy of `install.sh`. For the installer it only redirects to GitHub, so the file that runs is always the immutable, attested release asset.

| Request | Response |
| --- | --- |
| `https://getmultipass.dev/install.sh` | A temporary redirect (307) to `https://github.com/ninjudd/multipass/releases/latest/download/install.sh`, which GitHub in turn redirects to the newest release's file |
| `https://getmultipass.dev/<tag>/install.sh`, such as `/v0.2.0/install.sh` | A temporary redirect to `https://github.com/ninjudd/multipass/releases/download/<tag>/install.sh` |
| `https://getmultipass.dev/` | `site/index.html`, the landing page |
| `https://www.getmultipass.dev/…` | A permanent redirect to the same path on `getmultipass.dev` |

The domain's DNS answers only for `getmultipass.dev` and `www.getmultipass.dev`. Vercel DNS adds an `ALIAS` for the `*` wildcard by default, and rollout removes it, so a made-up name such as `install.getmultipass.dev` does not resolve and cannot be mistaken for the real one.

Each redirect carries `Cache-Control: no-store`, so no cache serves an old target. GitHub resolves the newest release and sends `Cache-Control: no-cache` on its own redirect, so a release is live through the domain as soon as it is published. `.dev` is on browsers' HTTPS preload list, so browsers only ever load the domain over HTTPS, and Vercel issues and renews its certificate.

Whoever controls the registrar account, the Vercel team, or the domain's DNS can point the URL anywhere. These settings protect it:

| Protection | Where | State |
| --- | --- | --- |
| Auto-renew, so the domain cannot lapse and be registered by someone else | The registrar | Being set by the owner |
| Registrar lock, so the domain cannot be transferred away without unlocking it first | The registrar | Being set by the owner |
| Two-factor sign-in on the registrar account and for every member of the Vercel team | Both accounts | To confirm in rollout |
| CAA records naming the certificate authorities that may issue for the domain | Vercel DNS | Verified: Vercel DNS adds CAA records for Let's Encrypt, Sectigo, and Google Trust Services by default (`0 issue "letsencrypt.org"`, `0 issue "sectigo.com"`, `0 issue "pki.goog"`). Keep all three, because Vercel does not document which of them it falls back to when one fails, and removing one could stop a certificate renewing. |
| `0 issuewild ";"`, so no authority may issue a wildcard certificate | Vercel DNS | To add in rollout. `issuewild` governs only wildcard requests (RFC 8659 § 4.3), so the apex and `www` certificates, which name exact hosts, still issue under the `issue` records. Unverified that Vercel never puts a wildcard name into the certificate it requests for the apex, so rollout adds the record only after `vercel certs ls` shows certificates naming just the two hosts, and checks again after the first renewal. |
| DNSSEC | Vercel DNS | Not available, unverified with Vercel. Vercel's community forum says its DNS does not support DNSSEC, `.dev` domains included, and Vercel's documentation says nothing either way. |
| The README offers a pinned URL, GitHub's own URL, and the check-first install (§ 2.6) | `README.md` | In this project |

Without DNSSEC, someone who can forge DNS answers to a certificate authority could, in principle, get a certificate for the domain. CAA narrows that to the authorities it names. The check-first install and `gh attestation verify` do not depend on the domain at all, which is why the README keeps them.

### 2.10 Deploying the website

`.github/workflows/site.yml` deploys `site/` to Vercel on every push to `main` that changes `site/`, the workflow, `.github/vercel/`, or `check-site.sh`, and on `workflow_dispatch`. Vercel gets no access to the repository: the workflow pushes to Vercel, and no Vercel app is installed.

1. The job runs on `ubuntu-latest` with `permissions: contents: read`, in a GitHub environment named `production` whose deployment branches are limited to `main`. The environment holds the `VERCEL_TOKEN` secret, so a pull request's workflow, which never runs on `main`, cannot read it. The Vercel team and project IDs are environment variables, not secrets.
2. It checks out the pushed commit with `persist-credentials: false`, using `actions/checkout` pinned by commit SHA.
3. It runs `.github/scripts/check-site.sh static`. The guard fails unless every redirect whose source ends in `install.sh` points at a URL that starts with `https://github.com/ninjudd/multipass/releases/` and holds no `..` segment and no `%2e` in either case, because `curl` collapses `/releases/../../` before it sends the request, so such a URL passes the prefix check and still leaves the repository. No rewrite touches `install.sh`, `site/` holds no file named `install.sh`, and `vercel.json` sets no build command, framework, or function.
4. It runs `npm ci --ignore-scripts` in `.github/vercel/`, which installs exactly the locked Vercel CLI and runs none of its packages' install scripts.
5. It runs `vercel deploy --prod` in `site/` with the token.
6. It runs `.github/scripts/check-site.sh live https://getmultipass.dev`, which fails unless `/install.sh` and `/v0.0.0/install.sh` answer with a redirect into `https://github.com/ninjudd/multipass/releases/`, checked by the same rule as the static check, and `cache-control: no-store`. When it fails, the job runs `vercel rollback` to the previous production deployment and fails, so the bad redirect stays live only for the seconds between the deploy and the check.

The token is created for the Vercel team, with an expiry, and is replaced before it expires. Whether Vercel can scope a token to one project rather than the whole team is unverified; if it can, the token is scoped to this project.

The Vercel CLI is the one piece of third-party code in this design, and it runs only in this job, never in the release workflow and never in the binary. It still matters: it runs with the token, so a compromised CLI could deploy a different redirect. The lock file means the CLI changes only in a reviewed pull request, and the live check runs `curl`, not the CLI, so it catches a bad redirect the CLI deployed. What stays is the risk that someone who can merge to `main`, or who holds the token, changes the website. Merging already requires a clean Projector review, and anyone who can merge can already change the installer itself, so the website adds no more than that. The guard catches the one change that would hurt users, a redirect to another script, and the check-first install and GitHub's own URL (§ 2.6) never touch the domain.

## 3. Why this design

- **Build from source first.** With no dependencies, a release build takes about three seconds, so building on your own Mac costs nothing and removes the build server from what you trust. You trust GitHub to serve the tagged source and your own toolchain to compile it, the same trust `cargo install --path .` asks for today.
- **An attestation, not a checksum, for the binary.** A checksum from the same release proves only that the download is complete. The attestation is signed through Sigstore with a certificate that names the repository, the workflow file, the branch the run started from, and the commit it built, and the installer requires `main` and the commit the tag names, so a binary uploaded by anyone who stole a token, or built from code that is not in the repository, fails the check. Publishing the bundle as an asset lets `gh` check it without a login, and lets any Sigstore client, such as `cosign`, check it too.
- **Refuse when nothing can check.** Installing an unchecked binary by default would make the safe path the unusual one. The two remedies are one install each, and `MULTIPASS_UNVERIFIED=1` stays for someone who accepts the risk by name.
- **Exact version tags only, no moving `v0` tag.** Projector's installer follows a tag that every release moves. multipass finds the newest release from GitHub's `releases/latest` redirect instead, which needs no tag to move, and every tag it reads is immutable. A tag that moves is one more thing an attacker could move.
- **The version comes from `Cargo.toml`.** A tag pushed by hand can disagree with the code it names. Deriving the tag from the merged version, and checking `--version` on the built binary, keeps them equal by construction.
- **Least privilege by job.** The build runs the compiler with a read-only token. The job that can write releases and sign attestations never checks out or runs the repository's code.
- **Reproducible, and checked on every release.** Rebuilding in a second directory costs a few seconds and keeps the build reproducible, so `install.sh verify` keeps working.
- **`~/.local/bin` and a receipt, never shell files.** A user directory needs no `sudo`. The installer prints the PATH line rather than editing a startup file, as Projector's does, because a startup file is your configuration. The receipt lets `uninstall` remove only a file the installer wrote, which matters because Canonical's Multipass ships a command with the same name.
- **Reuse.** The installer follows Projector's: the checkout-or-release split, the environment overrides, aligned rows with warning markers, the `status` command, idempotent reruns, and never replacing your configuration. It replaces nothing in multipass, which has no installer today.
- **The domain redirects to GitHub, and Vercel serves it.** A domain is easier to type and to remember than a release URL, but every host that serves the installer can change it. Redirecting keeps the file of record on GitHub, immutable and attested, so the domain adds only a hop. Vercel already holds the domain's DNS, and whoever holds DNS can point the domain anywhere, so serving from Vercel adds no party you trust. GitHub Pages, the other choice, would add a second one: the repository's Pages site, which the Projector site workflow deploys from `main` through Projector's site action at a moving tag. Pages also cannot send an HTTP redirect, which `curl` needs (Pages offers only an HTML page that a browser follows), cannot set headers (it sends `Cache-Control: max-age=600` on every file), and publishes only Markdown and HTML through that action, so it would need a change to Projector and would serve `main`'s unreleased installer. Moving the Pages site to the domain would also put the plans and review summaries on the product's front page.
- **The website deploys from a workflow, not through Vercel's GitHub app.** A change to the website goes live when it merges, as the owner wants, while Vercel gets no access to the repository. Vercel's documentation lists its GitHub app's repository permissions as read and write on contents and on workflows, so installing it would let a third party change any file, `release.yml` included. The workflow pushes to Vercel with a token instead, and the token reaches only `main`.
- **Rejected: a Homebrew tap.** Homebrew's `multipass` name belongs to Canonical's cask, which installs `/usr/local/bin/multipass`. A tap formula named `multipass` would need its full name, `ninjudd/tap/multipass`, everywhere, would put a second `multipass` command on PATH for anyone with the cask, and would be another repository and another release step to keep in sync. The installer covers the same users without those costs. Revisit if multipass is renamed.
- **`upgrade` runs the installer, through `curl`, only when you ask.** It gives an upgrade exactly the installer's checks, and adds none of its own to keep in step, as Projector's `project upgrade` reruns Projector's installer. It adds nothing an attacker lacks, because any program running as you can already run `curl` and `bash`. What it must not do is reach the network on its own, so it never checks in the background: a password manager that phones home on every use tells the server when you use it.
- **Rejected: new-version notices.** A notice needs a check that runs without being asked. `upgrade --check` answers the same question when you ask it.
- **Rejected for now: Linux binaries.** CI runs only on macOS, and the clipboard support in progress is macOS only. The source build works wherever the tagged source builds, so Linux users with Rust can already install, and the binary step says so.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| With `cargo` on PATH, run the release one-liner with `HOME` in a temporary directory | Rows `release`, `fetched`, `built`, `installed`, then `not-on-path`. `~/.local/bin/multipass --version` prints the release's version. |
| Run it again | `current`, and the binary's modification time is unchanged |
| With `PATH` lacking `cargo` but holding `gh` | `checksum`, then `attested` naming `release.yml` and the tag |
| The same, against a `file://` mirror through `MULTIPASS_DOWNLOAD_URL` with one byte of the binary changed and `SHA256SUMS` rewritten to match | `checksum` passes, `gh attestation verify` fails, the installer exits 65, and nothing is installed |
| With neither `cargo` nor `gh` | Exit 69 with the message in § 2.1 step 5, and nothing installed |
| The same with `MULTIPASS_UNVERIFIED=1` | Installs, with the `unverified` warning row, and the receipt says `method unverified` |
| Put another executable named `multipass` earlier on PATH, then run `status` | `shadowed` naming that file |
| Change the installed binary by hand, then `uninstall` | `user-owned`, and the file stays |
| `uninstall` after a clean install | The binary and the receipt are gone, and `kept` names the stores |
| After an install and an uninstall, list files under `HOME` that changed | Nothing remains changed. `~/.multipass` and every shell startup file were never touched. |
| `./install.sh` in a checkout with no network | Builds and installs the checkout, with no `fetched` row |
| Merge a pull request that raises the version | A published, immutable release `v<version>` with the five assets. `gh attestation verify` on the binary passes with `--signer-workflow`, `--source-ref refs/heads/main`, and `--source-digest` set to the commit the tag names, and fails with `--source-ref refs/tags/v<version>` or with any other commit |
| Run the release workflow by hand from a branch other than `main` | `build` fails at its first step, and nothing is published |
| Raise the version in `Cargo.toml` but not in `Cargo.lock` | CI fails on `cargo test --locked` in the pull request |
| `install.sh verify <version>` with rustup's toolchain from the build info | `reproduced` |
| `multipass upgrade` on an install that is one release behind | The installer's rows, ending in `installed` with the new version, and `multipass --version` prints it |
| `multipass upgrade` on a binary from `cargo install` | Exit 69 naming that path, and nothing downloaded |
| `multipass upgrade --check` when current, and when a release behind | Exit 0 and exit 1, with the messages in § 2.3 |
| `multipass upgrade` with `gh` on PATH, against an `install.sh` changed by one byte | Exit 65, and the installer never runs |
| A pull request that points the `/install.sh` redirect at another host | CI fails on `check-site.sh static`, naming the redirect |
| A pull request's workflow that tries to read `VERCEL_TOKEN` | The secret is empty, because the `production` environment admits only `main` |
| A push to `main` that changes `site/index.html` | The site workflow deploys it, and `check-site.sh live` passes |
| The site workflow's live check against a deployment whose redirect points elsewhere | The job runs `vercel rollback` and fails |
| `dig +short install.getmultipass.dev` | Nothing, because the wildcard record is gone |
| `curl -sI https://getmultipass.dev/install.sh` | `HTTP/2 307`, `location: https://github.com/ninjudd/multipass/releases/latest/download/install.sh`, and `cache-control: no-store` |
| `curl -sI https://getmultipass.dev/v0.1.0/install.sh` | A 307 to `https://github.com/ninjudd/multipass/releases/download/v0.1.0/install.sh` |
| `curl -sI http://getmultipass.dev/install.sh` and `curl -sI https://www.getmultipass.dev/install.sh` | Each redirects to `https://getmultipass.dev/install.sh`, never serving a file over plain HTTP |
| `dig +short getmultipass.dev CAA` | Only the authorities § 2.9 names, and `0 issuewild ";"` |
| `curl -fsSL https://getmultipass.dev/install.sh \| bash` with `HOME` in a temporary directory | The same rows as the first row of this table |

Tests that must fail before the change and pass after it:

- **`tests/install.sh`**, run by CI on the checkout. It checks each row from a checkout install, the receipt's fields, that a rerun prints `current` and leaves the file alone, that `status` reports `current`, that `uninstall` refuses a file whose SHA-256 differs from the receipt, and that nothing under `HOME` changes except the binary and the receipt. Catches an installer that edits a startup file or the store directory, a rerun that reinstalls, and an uninstall that deletes someone else's `multipass`.
- **`upgrade` against fake programs**, in `src/upgrade.rs`. A fake `curl` writes a script and a fake `gh` passes or fails. Checks that a failing `gh` stops `upgrade` before `bash` runs, that a named version reaches both the URL and `MULTIPASS_VERSION`, that a missing receipt or one naming another path stops it, and that `--check` parses the tag from the redirect and exits 1 for a newer release. Catches an upgrade that runs an installer whose check failed, and one that installs a second copy beside the first.
- **Argument parsing** for `upgrade`, `upgrade <version>`, and `upgrade --check`, and rejecting `--check` with a version.
- **`check-site.sh static` against bad `vercel.json` files**, run in CI beside the real one: a redirect to another host, a redirect to `github.com/ninjudd/multipass` outside `/releases/`, a destination that climbs out of `/releases/` with `..` or `%2E%2E`, a rewrite of `/install.sh`, and an `install.sh` file in `site/`. Each must fail. Catches a guard that checks only the first redirect, or that accepts a look-alike URL such as `https://github.com/ninjudd/multipass-releases/`.
- **The tampered mirror**, in `tests/install.sh` once a release exists. Catches an installer that trusts `SHA256SUMS`, or that ignores `gh`'s exit status.
- **The release build's second build**, in `release.yml`. Catches a change that makes the binary depend on the build path or the time.

The release rows of the table need a real release, so the first release, published by `workflow_dispatch` once this merges, is where they are checked.

## 5. Cost

None of this changes the multipass binary, so commands cost what they cost today. An install from source downloads a source archive of a few hundred kilobytes and builds in about three seconds; one from a binary downloads under a megabyte. The release workflow runs a macOS job of a few minutes for each release.

## 6. Rollout

1. Merge the installer and the release workflow.
2. In the repository's settings, turn on immutable releases, and add a tag ruleset that blocks updating and deleting tags matching `v*`. Only the repository owner can change these.
3. Publish the first release, `v0.1.0`, from the current version by running the release workflow by hand.
4. The domain's nameservers already point at Vercel. Confirm auto-renew and the registrar lock at the registrar, and two-factor sign-in on the registrar account and for every member of the Vercel team. Remove the default `*` `ALIAS` record.
5. Create the Vercel project on that team and add `getmultipass.dev` and `www.getmultipass.dev` to it. Create the `production` environment limited to `main`, a team token with an expiry, and the `VERCEL_TOKEN` secret and the two ID variables in that environment. Run the site workflow by hand once. Until step 3's release exists, the redirect leads to a missing file.
6. Once `vercel certs ls` shows certificates naming only the two hosts, add `0 issuewild ";"`.
7. Check the release and domain rows of § 4, then point the README's Install section at the one-liner.

## 7. Open questions

### 7.1 How the domain's Vercel project deploys

Decided by the owner: a small website in `site/`, deployed on every push to `main` by a GitHub Actions workflow with a pinned Vercel CLI, as § 2.10 describes. The domain is `getmultipass.dev` on Vercel's DNS, and § 3 says why Vercel rather than GitHub Pages serves it. The alternatives were:

- **Deploy by hand:** no token in GitHub, but what is served can drift from `main`, and a website someone edits should go live when its change merges.
- **Vercel's GitHub app:** deploys on every merge too, but Vercel's documentation lists the app's repository permissions as read and write on contents and on workflows, so a third party could change any file, `release.yml` included. The workflow gets the same result with Vercel given no access to the repository.
- **GitHub Pages instead of Vercel:** § 3 gives the costs: a second party that can change what the domain serves, no HTTP redirects, fixed caching, and a change to Projector.

### 7.2 Whether multipass itself may reach the network

Decided by the owner: `multipass upgrade`, which reaches the network only when you type it, as § 2.3 describes. multipass contains no network code; `upgrade` downloads the installer with `/usr/bin/curl`, checks its attestation when `gh` is installed, and runs it, so an upgrade gets the installer's checks. `upgrade --check` only reports. Nothing runs in the background, and multipass shows no new-version notices. A running session-unlock agent ends after an upgrade through the session-unlock plan's binary check (§ 2.7).

Two details were left to the plan, and § 2.3 settles them:

- **A temporary file, not a pipe into `bash`.** Downloading first is what lets `upgrade` check the installer's attestation before any of it runs. A pipe starts running the script before the download ends.
- **The version is an argument, `multipass upgrade 0.2.0`.** `--version` already prints multipass's own version, so an option of that name would mean two things.

The rejected alternative was no `upgrade` command, upgrading by running the installer again.

### 7.3 Deferred

- **A CLI shipped inside `Multipass.app`.** Deferred to the passkeys plan, as § 2.7 describes.
- **Linux binaries.** Deferred until Linux support is planned. The release workflow would gain an Ubuntu build job, and the binary step would pick the asset for `uname`.

### 7.4 Decided

- **Where the installer is served.** The owner chose a domain of its own: `getmultipass.dev`, with its DNS on a Vercel team. The install URL is `https://getmultipass.dev/install.sh`, which redirects to the release asset, and the redirect-only design and the protections in § 2.9 follow from that.

## 8. Background

- **Projector's installer.** [Projector](https://github.com/ninjudd/projector)'s `install.sh` installs a release when piped from `curl` and the checkout it sits in otherwise, and never needs Git. It reads overrides such as `PROJECTOR_REF` from the environment, links into `~/.local/bin` and warns when that is not on PATH, prints one aligned row for each step, has a `status` command, and its CLI's `project upgrade` downloads and reruns the released installer. It follows the tag `v0`, which every release moves, and its documentation notes that its website serves that file from a cache that can trail a release by a few minutes.
- **The Pages site.** The `Projector site` workflow deploys the repository's Pages site, `https://ninjudd.io/multipass/`, through `ninjudd/projector/actions/site@v0`. The action copies `README.md` and the Markdown and HTML files under `docs/` into the site, and nothing else. GitHub reports the site's HTTPS as not enforced.
- **A build from source is fast and repeatable.** A clean `cargo build --release --locked --offline` of the current `main` took 2.6 seconds on an Apple silicon Mac and wrote a 420,704-byte arm64 binary. Building the same commit in two checkouts at different paths, with the same toolchain, gave identical bytes, but only because the two paths had the same length. Building it at `ra` and at `rb-much-longer-name` with rustup's 1.97.1 gave binaries that differ in 48 bytes: the `LC_UUID` load command and the code signature over it. The linker records each object file's path for debuggers, and those paths shift the bytes it hashes into the UUID, even though `strip` later removes them. Linking with `-Wl,-oso_prefix,.` records the paths relative to the directory cargo runs in, which then gives identical bytes for both targets at any path, as long as the target directory sits inside it and the path is the physical one: macOS's `TMPDIR` lies under the `/var` symlink, and the linker resolves `.` to `/private/var`. The binary embeds the toolchain's standard-library source paths, which differ between rustup's and Homebrew's toolchains, and the SDK version in its `LC_BUILD_VERSION` load command, so reproducing a release needs the same rustup toolchain and the same SDK version. The linker signs it ad hoc, and that signature is part of the reproducible bytes.
- **What an attestation's certificate records.** GitHub's CLI publishes its releases from a workflow dispatched on its default branch. Its attestation for `gh_2.106.0_linux_386.tar.gz` records `sourceRepositoryRef` as `refs/heads/trunk`, `githubWorkflowTrigger` as `workflow_dispatch`, and `sourceRepositoryDigest` as the commit that `api.github.com/repos/cli/cli/commits/v2.106.0` returns for the tag. Verifying it with `--source-ref refs/tags/v2.106.0` failed, `--source-ref refs/heads/trunk` with that `--source-digest` passed, and the same with a wrong digest failed.
- **Attestations without a login.** The GitHub API returns a public repository's attestations without a token, but `gh attestation verify` without `--bundle` stops and asks for `gh auth login`, because it fetches the attestations through the API. With `--bundle` and no login, it verified the attestation above. With a bundle, `gh` checks the signature against Sigstore's trusted root, which it fetches and caches without a GitHub login (`--custom-trusted-root` takes a saved copy for a machine with no network). It then checks the certificate's repository, workflow, ref, and commit against `--repo`, `--signer-workflow`, `--source-ref`, and `--source-digest`, and the attested digest against the file. It never asks GitHub whether the attestation is still listed, so a bundle someone deleted from GitHub would still verify. That does not weaken the check, since the signature and the certificate are what prove where the file came from.
- **Caching.** GitHub Pages answered the repository's site with `cache-control: max-age=600`. GitHub's `releases/latest/download/<file>` URL answered with a 302 to the newest release's file and `cache-control: no-cache`.
- **The domain's DNS.** The `.dev` registry delegates the domain to `ns1.vercel-dns.com` and `ns2.vercel-dns.com`. Vercel DNS lists, by default, CAA records for `pki.goog`, `sectigo.com`, and `letsencrypt.org`, and `ALIAS` records to Vercel for the apex and for the `*` wildcard. Vercel's community forum reports that Vercel DNS does not support DNSSEC, `.dev` included. Vercel's documentation requires `0 issue "letsencrypt.org"` in any custom CAA record, and does not say whether it also issues through the other two. Vercel's older documentation lists its GitHub app's permissions as read and write on repository contents, and a later changelog adds read and write on workflows.
- **The name.** Homebrew has no `multipass` formula. Its `multipass` cask is Canonical's Multipass, at version 1.17.2, which installs a package that puts a `multipass` command in `/usr/local/bin`.
