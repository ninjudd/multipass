#!/usr/bin/env bash
#
# Runs ./install.sh with HOME in a temporary directory and checks its rows,
# its receipt, a rerun, status, uninstall, and that nothing else under HOME
# changes. The release paths run against a file:// mirror made from this
# checkout, so the test needs no network and no published release.
#
#   tests/install.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/multipass-install-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# cargo and rustup find their toolchains under HOME, so keep them pointing at
# the real ones before HOME moves.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export HOME="$WORK/home"
unset XDG_DATA_HOME MULTIPASS_BIN_DIR MULTIPASS_VERSION MULTIPASS_BUILD MULTIPASS_UNVERIFIED \
  MULTIPASS_REPO MULTIPASS_DOWNLOAD_URL MULTIPASS_ARCHIVE_URL MULTIPASS_OFFLINE
export NO_COLOR=1
BIN="$HOME/.local/bin/multipass"
RECEIPT="$HOME/.local/share/multipass-install/receipt"
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
FAILURES=0

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  FAILURES=$((FAILURES + 1))
}

# Runs a command, keeping its combined output in $OUT and status in $STATUS.
run() {
  set +e
  OUT="$("$@" 2>&1)"
  STATUS=$?
  set -e
}

expect_status() {
  [ "$STATUS" = "$1" ] || fail "$2: exit $STATUS, expected $1; output:"$'\n'"$OUT"
}

# Checks that a row named $1 whose message contains $2 was printed.
expect_row() {
  printf '%s\n' "$OUT" | awk -v name="$1" -v text="$2" '$1 == name && index($0, text) { found = 1 } END { exit !found }' ||
    fail "$3: no $1 row with \"$2\"; output:"$'\n'"$OUT"
}

expect_no_row() {
  ! printf '%s\n' "$OUT" | grep -Eq "^$1 " || fail "$2: unexpected $1 row; output:"$'\n'"$OUT"
}

receipt() {
  awk -v key="$1" '$1 == key { sub(/^[^ ]+ /, ""); print; exit }' "$RECEIPT"
}

sha256() {
  shasum -a 256 "$1" | cut -d ' ' -f 1
}

mtime() {
  stat -f %m "$1" 2>/dev/null || stat -c %Y "$1"
}

# Every file under HOME with its digest, except the two the installer owns.
snapshot() {
  (cd "$HOME" && find . -type f ! -path ./.local/bin/multipass ! -path ./.local/share/multipass-install/receipt \
    -exec shasum -a 256 {} + | sort)
}

mkdir -p "$HOME/.multipass"
printf 'not a real store\n' >"$HOME/.multipass/store.age"
printf 'export PATH="/usr/bin:$PATH"\n' >"$HOME/.zshrc"
printf '# bash\n' >"$HOME/.bashrc"
BEFORE="$(snapshot)"

# A checkout install builds the checkout and fetches nothing.
run "$ROOT/install.sh"
expect_status 0 "checkout install"
expect_row built "$VERSION with rustc" "checkout install"
expect_row installed "~/.local/bin/multipass $VERSION (built from" "checkout install"
expect_row not-on-path 'export PATH="$HOME/.local/bin:$PATH"' "checkout install"
expect_no_row fetched "checkout install"
[ "$("$BIN" --version)" = "multipass $VERSION" ] || fail "the installed binary does not print multipass $VERSION"
[ "$(receipt version)" = "$VERSION" ] || fail "receipt version is $(receipt version)"
[ "$(receipt method)" = checkout ] || fail "receipt method is $(receipt method)"
[ "$(receipt path)" = "$BIN" ] || fail "receipt path is $(receipt path)"
[ "$(receipt sha256)" = "$(sha256 "$BIN")" ] || fail "receipt sha256 does not match the binary"
[ "$(receipt source)" = "$ROOT" ] || fail "receipt source is $(receipt source)"
[[ "$(receipt installed)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
  fail "receipt installed is $(receipt installed)"

# A rerun of the same checkout leaves the file alone.
touch -t 200001010000 "$BIN"
before_mtime="$(mtime "$BIN")"
run "$ROOT/install.sh"
expect_status 0 "rerun"
expect_row current "~/.local/bin/multipass $VERSION" "rerun"
expect_no_row installed "rerun"
[ "$(mtime "$BIN")" = "$before_mtime" ] || fail "a rerun rewrote the binary"

run "$ROOT/install.sh" status
expect_status 0 "status"
expect_row installed "~/.local/bin/multipass $VERSION" "status"
expect_row current "$VERSION matches the checkout" "status"

# Another multipass earlier on PATH shadows the installed one, and one later
# on PATH is listed.
mkdir -p "$WORK/early" "$WORK/late"
printf '#!/bin/sh\n' >"$WORK/early/multipass"
printf '#!/bin/sh\n' >"$WORK/late/multipass"
chmod +x "$WORK/early/multipass" "$WORK/late/multipass"
run env PATH="$WORK/early:$HOME/.local/bin:$WORK/late:$PATH" "$ROOT/install.sh" status
expect_row shadowed "$WORK/early/multipass comes first on PATH" "shadowed status"
expect_row other "$WORK/late/multipass" "shadowed status"
expect_no_row not-on-path "shadowed status"

# A file changed by hand is no longer the installer's to remove.
printf 'x' >>"$BIN"
run "$ROOT/install.sh" status
expect_row modified "no longer matches" "status after a change by hand"
run "$ROOT/install.sh" uninstall
expect_status 0 "uninstall of a changed file"
expect_row user-owned "~/.local/bin/multipass" "uninstall of a changed file"
[ -f "$BIN" ] || fail "uninstall removed a file that did not match the receipt"

# Installing again replaces the changed file, and uninstall then removes it.
run "$ROOT/install.sh"
expect_row installed "~/.local/bin/multipass $VERSION" "reinstall over a changed file"
run "$ROOT/install.sh" uninstall
expect_status 0 "uninstall"
expect_row removed "~/.local/bin/multipass" "uninstall"
expect_row kept "your stores" "uninstall"
[ ! -e "$BIN" ] || fail "uninstall left the binary"
[ ! -e "$RECEIPT" ] || fail "uninstall left the receipt"

# A rerun without MULTIPASS_BIN_DIR replaces the copy the receipt names
# rather than installing a second one, so uninstall then removes that copy.
run env MULTIPASS_BIN_DIR="$HOME/bin" "$ROOT/install.sh"
expect_row installed "~/bin/multipass $VERSION" "install into MULTIPASS_BIN_DIR"
run "$ROOT/install.sh"
expect_status 0 "rerun without MULTIPASS_BIN_DIR"
expect_row current "~/bin/multipass $VERSION" "rerun without MULTIPASS_BIN_DIR"
[ ! -e "$BIN" ] || fail "a rerun without MULTIPASS_BIN_DIR installed a second copy"
run "$ROOT/install.sh" uninstall
expect_row removed "~/bin/multipass" "uninstall after a rerun without MULTIPASS_BIN_DIR"
[ ! -e "$HOME/bin/multipass" ] || fail "uninstall left the copy in MULTIPASS_BIN_DIR"
rm -rf "$HOME/bin" "$BIN"

# A release, from a mirror. The installer copied out of the checkout installs
# a release rather than the checkout.
MIRROR="$WORK/mirror"
mkdir -p "$MIRROR/archive" "$MIRROR/download/v$VERSION" "$WORK/release"
cp "$ROOT/install.sh" "$WORK/release/install.sh"
git -C "$ROOT" archive --format=tar.gz --prefix="multipass-$VERSION/" HEAD >"$MIRROR/archive/v$VERSION.tar.gz"
export MULTIPASS_VERSION="$VERSION"
export MULTIPASS_ARCHIVE_URL="file://$MIRROR/archive"
export MULTIPASS_DOWNLOAD_URL="file://$MIRROR/download"

# A checkout build names no release, even at the release's version, so
# status outside the checkout calls it stale, and the release installs over
# it. A fake curl answers status's one request, for where releases/latest
# redirects.
run "$ROOT/install.sh"
expect_row installed "~/.local/bin/multipass $VERSION (built from" "checkout install before a release"
mkdir -p "$WORK/fake-curl"
printf '#!/bin/sh\nprintf %%s https://github.com/ninjudd/multipass/releases/tag/v%s\n' "$VERSION" >"$WORK/fake-curl/curl"
chmod +x "$WORK/fake-curl/curl"
run env PATH="$WORK/fake-curl:$PATH" bash "$WORK/release/install.sh" status
expect_status 0 "status of a checkout build outside the checkout"
expect_row stale "a checkout build, not a release; v$VERSION is the newest" "status of a checkout build outside the checkout"
expect_no_row current "status of a checkout build outside the checkout"

run bash "$WORK/release/install.sh"
expect_status 0 "release source install"
expect_row release "ninjudd/multipass v$VERSION" "release source install"
expect_row fetched "v$VERSION source, sha256" "release source install"
expect_row built "v$VERSION with rustc" "release source install"
expect_row installed "~/.local/bin/multipass $VERSION (built from source)" "release source install"
[ "$(receipt method)" = source ] || fail "release source receipt method is $(receipt method)"
[ "$(receipt source)" = "ninjudd/multipass v$VERSION" ] || fail "release source receipt source is $(receipt source)"

run bash "$WORK/release/install.sh"
expect_row current "~/.local/bin/multipass $VERSION" "release rerun"
expect_no_row fetched "release rerun"

if [ "$(uname -s)" = Darwin ]; then
  # The binary path, with neither cargo nor gh on PATH.
  cp "$BIN" "$MIRROR/download/v$VERSION/multipass-$VERSION-macos"
  (cd "$MIRROR/download/v$VERSION" && shasum -a 256 "multipass-$VERSION-macos" >SHA256SUMS)
  run bash "$WORK/release/install.sh" uninstall
  BARE_PATH=/usr/bin:/bin:/usr/sbin:/sbin

  run env PATH="$BARE_PATH" bash "$WORK/release/install.sh"
  expect_status 69 "binary install with neither cargo nor gh"
  printf '%s\n' "$OUT" | grep -q 'MULTIPASS_UNVERIFIED=1 installs it unchecked' ||
    fail "binary install with neither cargo nor gh did not say how to go on; output:"$'\n'"$OUT"
  [ ! -e "$BIN" ] || fail "a binary install with neither cargo nor gh installed something"

  printf '0%.0s' {1..64} >"$WORK/zeros"
  (cd "$MIRROR/download/v$VERSION" && printf '%s  %s\n' "$(cat "$WORK/zeros")" "multipass-$VERSION-macos" >SHA256SUMS)
  run env PATH="$BARE_PATH" MULTIPASS_UNVERIFIED=1 bash "$WORK/release/install.sh"
  expect_status 65 "binary install with a damaged download"
  [ ! -e "$BIN" ] || fail "a damaged download was installed"
  (cd "$MIRROR/download/v$VERSION" && shasum -a 256 "multipass-$VERSION-macos" >SHA256SUMS)

  run env PATH="$BARE_PATH" MULTIPASS_UNVERIFIED=1 bash "$WORK/release/install.sh"
  expect_status 0 "unverified binary install"
  expect_row checksum "matches SHA256SUMS" "unverified binary install"
  expect_row unverified "without checking where the binary came from" "unverified binary install"
  expect_row installed "~/.local/bin/multipass $VERSION (unverified binary)" "unverified binary install"
  [ "$(receipt method)" = unverified ] || fail "unverified receipt method is $(receipt method)"

  # verify, against a release whose binary is the checkout build, so its
  # slice never matches. A fake rustup runs the cargo and rustc on PATH,
  # whatever version it is asked for.
  mkdir -p "$WORK/fake-rustup"
  printf '#!/bin/sh\n[ "$1" = run ] || exit 1\nshift 2\nexec "$@"\n' >"$WORK/fake-rustup/rustup"
  chmod +x "$WORK/fake-rustup/rustup"
  lipo -create "$BIN" -output "$MIRROR/download/v$VERSION/multipass-$VERSION-macos"
  INFO="$MIRROR/download/v$VERSION/multipass-$VERSION.buildinfo"
  RUST="$(rustc --version | cut -d ' ' -f 2)"

  # The build info comes from the build verify distrusts, so a flag in it
  # that names a program to run stops verify before anything is built.
  printf '#!/bin/sh\ntouch "%s"\nexit 1\n' "$WORK/linker-ran" >"$WORK/linker"
  chmod +x "$WORK/linker"
  printf 'rustc-release %s\nrustflags -C linker=%s\nmacosx_deployment_target 11.0\n' "$RUST" "$WORK/linker" >"$INFO"
  run env PATH="$WORK/fake-rustup:$PATH" bash "$WORK/release/install.sh" verify
  expect_status 65 "verify with a linker in the build info's rustflags"
  printf '%s\n' "$OUT" | grep -q "build info's rustflags are not" ||
    fail "verify with a linker in the build info's rustflags did not name the field; output:"$'\n'"$OUT"
  [ ! -e "$WORK/linker-ran" ] || fail "verify ran the linker the build info named"
  printf 'rustc-release %s\nrustflags -C link-arg=-Wl,-oso_prefix,.\nmacosx_deployment_target 11.0 x\n' "$RUST" >"$INFO"
  run env PATH="$WORK/fake-rustup:$PATH" bash "$WORK/release/install.sh" verify
  expect_status 65 "verify with a deployment target that is not a version"

  # verify checks the source as an install from source does, before it
  # builds anything from it.
  printf 'rustc-release %s\nrustflags -C link-arg=-Wl,-oso_prefix,.\nmacosx_deployment_target 11.0\n' "$RUST" >"$INFO"
  mv "$MIRROR/archive/v$VERSION.tar.gz" "$WORK/good-source.tar.gz"
  mkdir -p "$WORK/bad-source/multipass-$VERSION"
  printf '[package]\nname = "multipass"\nversion = "9.9.9"\n' >"$WORK/bad-source/multipass-$VERSION/Cargo.toml"
  tar -czf "$MIRROR/archive/v$VERSION.tar.gz" -C "$WORK/bad-source" "multipass-$VERSION"
  run env PATH="$WORK/fake-rustup:$PATH" bash "$WORK/release/install.sh" verify
  expect_status 65 "verify of a source that names another version"
  printf '%s\n' "$OUT" | grep -q "Cargo.toml says version 9.9.9" ||
    fail "verify of a source that names another version did not say so; output:"$'\n'"$OUT"
  mv "$WORK/good-source.tar.gz" "$MIRROR/archive/v$VERSION.tar.gz"

  # A slice that differs exits 65 and names each field that differs, even
  # where xcodebuild fails, as it does with only the Command Line Tools.
  printf '#!/bin/sh\nexit 1\n' >"$WORK/fake-rustup/xcodebuild"
  chmod +x "$WORK/fake-rustup/xcodebuild"
  printf 'rustc-release %s\nrustc-commit-hash 0000\nxcode Xcode 0.0\nsdk 0.0\nrustflags -C link-arg=-Wl,-oso_prefix,.\nmacosx_deployment_target 11.0\n' "$RUST" >"$INFO"
  run env PATH="$WORK/fake-rustup:$PATH" bash "$WORK/release/install.sh" verify
  expect_status 65 "verify of a slice that differs"
  expect_row differs "slice does not match the release" "verify of a slice that differs"
  expect_row xcode "the release used Xcode 0.0, this Mac has none" "verify of a slice that differs"
  expect_row sdk "the release used 0.0" "verify of a slice that differs"
fi

run bash "$WORK/release/install.sh" uninstall
expect_row removed "~/.local/bin/multipass" "final uninstall"

[ "$(snapshot)" = "$BEFORE" ] || fail "files under HOME changed:"$'\n'"$(diff <(printf '%s\n' "$BEFORE") <(snapshot) || true)"
[ ! -e "$RECEIPT" ] || fail "the receipt remains after the final uninstall"

if [ "$FAILURES" -gt 0 ]; then
  printf '%d install.sh checks failed\n' "$FAILURES" >&2
  exit 1
fi
printf 'install.sh checks passed\n'
