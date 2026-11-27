#!/usr/bin/env bash
#
# Builds the release assets for the commit checked out, into <out-dir>:
#
#   multipass-<version>-macos       the universal binary, arm64 and x86_64
#   install.sh                      the installer at this commit
#   SHA256SUMS                      the digests of those two files
#   multipass-<version>.buildinfo   what the build ran on, for install.sh verify
#
#   .github/scripts/build-release.sh <out-dir>
#
# Each target is built twice, from `git archive HEAD` unpacked at two
# different paths, and the script fails when any byte differs, so a change
# that makes the binary depend on its build path or the time cannot ship.
# The archive holds what GitHub's source archive for the tag holds, which is
# what install.sh verify rebuilds. The release workflow runs this on a pinned
# toolchain; see docs/projects/installer/readme.md § 2.5 and § 2.6.

set -euo pipefail

[ $# -eq 1 ] || {
  echo "usage: $0 <out-dir>" >&2
  exit 64
}
ROOT="$(git rev-parse --show-toplevel)"
OUT="$1"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# The physical path, because -oso_prefix . (below) strips the directory as
# getcwd reports it, and TMPDIR on macOS sits under the /var symlink.
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/multipass-release.XXXXXX")" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
BINARY="multipass-$VERSION-macos"
export MACOSX_DEPLOYMENT_TARGET=11.0
# The linker hashes the paths of the object files it records into LC_UUID,
# and their lengths shift the layout, so two builds at different paths
# differ. -oso_prefix . records them relative to the directory cargo runs in,
# which holds the target directory, so the bytes no longer depend on where
# the source is unpacked.
export RUSTFLAGS="-C link-arg=-Wl,-oso_prefix,."
unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
BUILD=(cargo build --release --locked --offline)

sha256() {
  shasum -a 256 "$1" | cut -d ' ' -f 1
}

# Unpacks HEAD at $WORK/$1 and builds every target there.
build_at() {
  local dir="$WORK/$1" target
  mkdir -p "$dir"
  git -C "$ROOT" archive --format=tar HEAD | tar -x -C "$dir"
  for target in "${TARGETS[@]}"; do
    (cd "$dir" && CARGO_TARGET_DIR="$dir/target" "${BUILD[@]}" --target "$target")
  done
}

build_at first
build_at second-build-elsewhere
for target in "${TARGETS[@]}"; do
  first="$WORK/first/target/$target/release/multipass"
  second="$WORK/second-build-elsewhere/target/$target/release/multipass"
  if ! cmp -s "$first" "$second"; then
    echo "::error::the $target build is not reproducible: two builds of the same commit differ" >&2
    exit 1
  fi
done

lipo -create -output "$OUT/$BINARY" \
  "$WORK/first/target/aarch64-apple-darwin/release/multipass" \
  "$WORK/first/target/x86_64-apple-darwin/release/multipass"
reported="$("$OUT/$BINARY" --version)"
if [ "$reported" != "multipass $VERSION" ]; then
  echo "::error::the binary says \"$reported\", not \"multipass $VERSION\"" >&2
  exit 1
fi
cp "$WORK/first/install.sh" "$OUT/install.sh"
(cd "$OUT" && shasum -a 256 "$BINARY" install.sh >SHA256SUMS)

# The build info is `key value` lines. The rustc-* lines are `rustc -vV`,
# one field each, so install.sh verify can name the toolchain to rebuild with
# and say which field differs on another Mac.
{
  printf 'tag v%s\n' "$VERSION"
  printf 'commit %s\n' "$COMMIT"
  printf 'rustc %s\n' "$(rustc --version)"
  rustc -vV | awk -F ': ' 'NF == 2 { key = tolower($1); gsub(/ /, "-", key); print "rustc-" key " " $2 }'
  printf 'xcode %s\n' "$(xcodebuild -version | paste -s -d ' ' -)"
  printf 'sdk %s\n' "$(xcrun --sdk macosx --show-sdk-version)"
  printf 'macosx_deployment_target %s\n' "$MACOSX_DEPLOYMENT_TARGET"
  printf 'rustflags %s\n' "$RUSTFLAGS"
  printf 'command RUSTFLAGS="%s" %s --target <target>, in the unpacked source with CARGO_TARGET_DIR=target\n' "$RUSTFLAGS" "${BUILD[*]}"
  for target in "${TARGETS[@]}"; do
    printf 'sha256-%s %s\n' "$target" "$(sha256 "$WORK/first/target/$target/release/multipass")"
  done
  printf 'sha256-universal %s\n' "$(sha256 "$OUT/$BINARY")"
} >"$OUT/multipass-$VERSION.buildinfo"

ls -l "$OUT"
cat "$OUT/multipass-$VERSION.buildinfo"
