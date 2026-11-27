#!/usr/bin/env bash
#
# Install multipass into ~/.local/bin from a tagged release, or from the
# checkout this script sits in.
#
#   curl -fsSL https://getmultipass.dev/install.sh | bash
#   curl -fsSL https://getmultipass.dev/install.sh | bash -s -- status
#   ./install.sh [install|status|uninstall]          from a checkout
#
# A release installs only code it can show came from its tag: with cargo on
# PATH it builds the tag's source, and otherwise it installs the prebuilt
# binary only after `gh attestation verify` proves the release workflow built
# it from that tag. The installer never touches your stores, ~/.multipass, or
# your shell's startup files. docs/projects/installer/readme.md is the design.

set -euo pipefail

# The directory holding this script, or nothing when bash reads it from stdin.
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
# A checkout is a script with multipass's Cargo.toml beside it. A copy of the
# script on its own, such as the one `multipass upgrade` downloads, is not.
CHECKOUT=""
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/Cargo.toml" ] &&
  grep -qx 'name = "multipass"' "$SCRIPT_DIR/Cargo.toml"; then
  CHECKOUT="$SCRIPT_DIR"
fi
RELEASE_REPO="${MULTIPASS_REPO:-ninjudd/multipass}"
DOWNLOAD_URL="${MULTIPASS_DOWNLOAD_URL:-https://github.com/$RELEASE_REPO/releases/download}"
ARCHIVE_URL="${MULTIPASS_ARCHIVE_URL:-https://github.com/$RELEASE_REPO/archive/refs/tags}"
BIN_DIR="${MULTIPASS_BIN_DIR:-$HOME/.local/bin}"
RECEIPT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/multipass-install"
RECEIPT="$RECEIPT_DIR/receipt"
TARGET="$BIN_DIR/multipass"
WORK=""

# Exit statuses, from sysexits.h.
EX_USAGE=64
EX_DATAERR=65
EX_UNAVAILABLE=69

row() {
  printf '%-14s %s\n' "$1" "$2"
}

warn_row() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    printf '\033[1;33m%-14s ⚠️  %s\033[0m\n' "$1" "$2"
  else
    printf '%-14s ⚠️  %s\n' "$1" "$2"
  fi
}

die() {
  local status="$1"
  shift
  printf 'install.sh: %s\n' "$*" >&2
  exit "$status"
}

# A path with $HOME shown as ~, for rows.
tilde() {
  case "$1" in
    "$HOME"/*) printf '~%s\n' "${1#"$HOME"}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    sha256sum "$1" | cut -d ' ' -f 1
  fi
}

# Downloads a URL to a file. Only https and file URLs are allowed, so a
# mirror can be a local directory but nothing is fetched in plain text.
fetch() {
  curl -fsSL --proto '=https,file' --tlsv1.2 -o "$2" "$1" ||
    die "$EX_UNAVAILABLE" "could not download $1"
}

make_work() {
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/multipass-install.XXXXXX")"
  trap 'rm -rf "$WORK"' EXIT
}

check_settings() {
  [[ "$RELEASE_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
    die "$EX_USAGE" "MULTIPASS_REPO must look like owner/name, not $RELEASE_REPO"
  case "${MULTIPASS_BUILD:-}" in
    "" | source | binary) ;;
    *) die "$EX_USAGE" "MULTIPASS_BUILD must be source or binary, not $MULTIPASS_BUILD" ;;
  esac
}

# Prints a version without a leading v, or fails when it is not one.
check_version() {
  local version="${1#v}"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
    die "$EX_USAGE" "$1 is not a release version such as 0.2.0"
  printf '%s\n' "$version"
}

# The newest release's version, read from where GitHub's releases/latest page
# redirects, which needs no API call and so no rate limit.
latest_version() {
  local url location
  url="https://github.com/$RELEASE_REPO/releases/latest"
  location="$(curl -fsS --proto '=https' -o /dev/null -w '%{redirect_url}' "$url")" ||
    die "$EX_UNAVAILABLE" "could not read the newest release from $url"
  case "$location" in
    */releases/tag/v*) check_version "${location##*/releases/tag/}" ;;
    *) die "$EX_UNAVAILABLE" "$RELEASE_REPO has no release yet ($url)" ;;
  esac
}

# The version a checkout's Cargo.toml names.
cargo_version() {
  sed -n 's/^version = "\(.*\)"$/\1/p' "$1/Cargo.toml" | head -n 1
}

receipt_get() {
  [ -f "$RECEIPT" ] || return 0
  awk -v key="$1" '$1 == key { sub(/^[^ ]+ /, ""); print; exit }' "$RECEIPT"
}

# True when the receipt records `path` and that file still has the recorded
# SHA-256, so the installer owns it.
installed_intact() {
  local path sum
  path="$(receipt_get path)"
  sum="$(receipt_get sha256)"
  [ -n "$path" ] && [ -f "$path" ] && [ "$(sha256 "$path")" = "$sum" ]
}

describe_method() {
  case "$1" in
    source) printf 'built from source\n' ;;
    binary) printf 'attested binary\n' ;;
    unverified) printf 'unverified binary\n' ;;
    checkout) printf 'built from %s\n' "$(tilde "$2")" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

# Builds the source in $1 into $WORK/target, and sets CANDIDATE to the binary
# and BUILT_WITH to the rustc version that built it.
build() {
  local src="$1" rustc
  rustc="$(cd "$src" && rustc --version | cut -d ' ' -f 2)"
  (cd "$src" && CARGO_TARGET_DIR="$WORK/target" cargo build --release --locked --offline --quiet) ||
    die 1 "cargo build --release --locked --offline failed in $(tilde "$src")"
  BUILT_WITH="$rustc"
  CANDIDATE="$WORK/target/release/multipass"
}

build_release_source() {
  local version="$1" archive="$WORK/source.tar.gz" src="$WORK/source"
  fetch "$ARCHIVE_URL/v$version.tar.gz" "$archive"
  row "fetched" "v$version source, sha256 $(sha256 "$archive")"
  mkdir "$src"
  tar -xzf "$archive" -C "$src" --strip-components 1 ||
    die "$EX_DATAERR" "could not unpack the v$version source archive"
  [ "$(cargo_version "$src")" = "$version" ] ||
    die "$EX_DATAERR" "the v$version source's Cargo.toml says version $(cargo_version "$src")"
  # One package in the lock file means multipass and nothing else, so the
  # build runs no code from outside the tagged source.
  [ "$(grep -c '^\[\[package\]\]$' "$src/Cargo.lock")" = 1 ] &&
    grep -qx 'name = "multipass"' "$src/Cargo.lock" ||
    die "$EX_DATAERR" "the v$version source's Cargo.lock lists packages other than multipass"
  build "$src"
  row "built" "v$version with rustc $BUILT_WITH"
}

install_release_binary() {
  local version="$1" binary="multipass-$version-macos" commit
  [ "$(uname -s)" = Darwin ] ||
    die "$EX_UNAVAILABLE" "there is no prebuilt multipass for $(uname -s); install Rust from https://rustup.rs and run the installer again"
  local gh=""
  command -v gh >/dev/null 2>&1 && gh=gh
  if [ -z "$gh" ] && [ "${MULTIPASS_UNVERIFIED:-}" != 1 ]; then
    die "$EX_UNAVAILABLE" "cannot prove this binary was built from v$version -- install Rust (https://rustup.rs) to build it from source, or gh (https://cli.github.com) to check its attestation; MULTIPASS_UNVERIFIED=1 installs it unchecked"
  fi
  fetch "$DOWNLOAD_URL/v$version/$binary" "$WORK/$binary"
  fetch "$DOWNLOAD_URL/v$version/SHA256SUMS" "$WORK/SHA256SUMS"
  # The checksum comes from the same place as the binary, so it catches only
  # a truncated or corrupted download. The attestation is the real check.
  [ "$(awk -v f="$binary" '$2 == f { print $1 }' "$WORK/SHA256SUMS")" = "$(sha256 "$WORK/$binary")" ] ||
    die "$EX_DATAERR" "$binary does not match SHA256SUMS; the download is damaged, and nothing was installed"
  row "checksum" "matches SHA256SUMS"
  if [ -n "$gh" ]; then
    fetch "$DOWNLOAD_URL/v$version/multipass.sigstore.json" "$WORK/multipass.sigstore.json"
    commit="$(curl -fsS --proto '=https' -H 'Accept: application/vnd.github.sha' \
      "https://api.github.com/repos/$RELEASE_REPO/commits/v$version")" ||
      die "$EX_UNAVAILABLE" "could not read the commit v$version names from api.github.com, perhaps because its limit of 60 requests an hour is spent; nothing was installed"
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] ||
      die "$EX_UNAVAILABLE" "api.github.com did not answer with the commit v$version names; nothing was installed"
    # The release workflow runs on the merge to main and tags that commit
    # afterwards, so the certificate records refs/heads/main and the commit,
    # never the tag. --source-digest is what ties the binary to the tag.
    "$gh" attestation verify "$WORK/$binary" \
      --bundle "$WORK/multipass.sigstore.json" \
      --repo "$RELEASE_REPO" \
      --signer-workflow "$RELEASE_REPO/.github/workflows/release.yml" \
      --source-ref refs/heads/main \
      --source-digest "$commit" \
      --deny-self-hosted-runners >/dev/null ||
      die "$EX_DATAERR" "gh attestation verify rejected $binary, so it was not built from v$version by the release workflow; nothing was installed"
    row "attested" "built by release.yml on main at ${commit:0:7}, the commit v$version names"
    METHOD=binary
  else
    warn_row "unverified" "installed without checking where the binary came from"
    METHOD=unverified
  fi
  chmod 0755 "$WORK/$binary"
  CANDIDATE="$WORK/$binary"
}

# Copies the candidate into place with a rename, so a running multipass keeps
# its old file and never sees a half-written one, then writes the receipt.
place() {
  local version="$1" source="$2" sum tmp
  [ "$("$CANDIDATE" --version)" = "multipass $version" ] ||
    die "$EX_DATAERR" "the new binary does not say it is multipass $version; nothing was installed"
  mkdir -p "$BIN_DIR" "$RECEIPT_DIR"
  tmp="$BIN_DIR/.multipass.$$"
  cp "$CANDIDATE" "$tmp"
  chmod 0755 "$tmp"
  mv -f "$tmp" "$TARGET"
  sum="$(sha256 "$TARGET")"
  tmp="$RECEIPT.$$"
  {
    printf 'version %s\n' "$version"
    printf 'method %s\n' "$METHOD"
    printf 'path %s\n' "$TARGET"
    printf 'sha256 %s\n' "$sum"
    printf 'source %s\n' "$source"
    printf 'installed %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$tmp"
  mv -f "$tmp" "$RECEIPT"
  row "installed" "$(tilde "$TARGET") $version ($(describe_method "$METHOD" "$source"))"
}

# Warns when BIN_DIR is not on PATH or another multipass comes first, and
# lists every other multipass on PATH.
path_rows() {
  local first dir seen=":"
  case ":$PATH:" in
    *":$BIN_DIR:"* | *":$BIN_DIR/:"*) ;;
    *)
      local shown="$BIN_DIR"
      case "$BIN_DIR" in "$HOME"/*) shown="\$HOME${BIN_DIR#"$HOME"}" ;; esac
      warn_row "not-on-path" "add export PATH=\"$shown:\$PATH\" to your shell's startup file"
      ;;
  esac
  first="$(type -P multipass || true)"
  if [ -n "$first" ] && [ "$first" != "$TARGET" ]; then
    # Canonical's Multipass, a tool for Ubuntu virtual machines, installs a
    # command of the same name in /usr/local/bin.
    warn_row "shadowed" "$(tilde "$first") comes first on PATH"
  fi
  local IFS=:
  for dir in $PATH; do
    dir="${dir%/}"
    case "$seen" in *":$dir:"*) continue ;; esac
    seen="$seen$dir:"
    if [ -x "$dir/multipass" ] && [ "$dir/multipass" != "$TARGET" ] && [ "$dir/multipass" != "$first" ]; then
      row "other" "$(tilde "$dir/multipass")"
    fi
  done
}

cmd_install() {
  local version source
  make_work
  if [ -n "$CHECKOUT" ]; then
    command -v cargo >/dev/null 2>&1 ||
      die "$EX_UNAVAILABLE" "building this checkout needs cargo; install Rust from https://rustup.rs"
    version="$(cargo_version "$CHECKOUT")"
    build "$CHECKOUT"
    row "built" "$(tilde "$CHECKOUT") $version with rustc $BUILT_WITH"
    # A checkout can change without a version bump, so a rerun rebuilds and
    # compares the bytes rather than the version.
    if installed_intact && [ "$(receipt_get path)" = "$TARGET" ] &&
      [ "$(sha256 "$CANDIDATE")" = "$(receipt_get sha256)" ]; then
      row "current" "$(tilde "$TARGET") $version"
    else
      METHOD=checkout
      place "$version" "$CHECKOUT"
    fi
    path_rows
    return
  fi

  if [ -n "${MULTIPASS_VERSION:-}" ]; then
    version="$(check_version "$MULTIPASS_VERSION")"
  else
    version="$(latest_version)"
  fi
  row "release" "$RELEASE_REPO v$version"
  if [ "$(receipt_get version)" = "$version" ] && [ "$(receipt_get path)" = "$TARGET" ] && installed_intact; then
    row "current" "$(tilde "$TARGET") $version"
    path_rows
    return
  fi
  source="$RELEASE_REPO v$version"
  local how="${MULTIPASS_BUILD:-}"
  if [ -z "$how" ]; then
    if command -v cargo >/dev/null 2>&1; then how=source; else how=binary; fi
  fi
  if [ "$how" = source ]; then
    command -v cargo >/dev/null 2>&1 ||
      die "$EX_UNAVAILABLE" "MULTIPASS_BUILD=source needs cargo; install Rust from https://rustup.rs"
    build_release_source "$version"
    METHOD=source
  else
    install_release_binary "$version"
  fi
  place "$version" "$source"
  path_rows
}

cmd_status() {
  local newest="" version method path
  if [ -n "$CHECKOUT" ]; then
    newest="$(cargo_version "$CHECKOUT")"
    row "checkout" "$(tilde "$CHECKOUT") $newest"
  elif [ "${MULTIPASS_OFFLINE:-}" != 1 ]; then
    newest="$(latest_version)"
    row "release" "$RELEASE_REPO v$newest"
  fi
  version="$(receipt_get version)"
  if [ -z "$version" ]; then
    row "not-installed" "no receipt at $(tilde "$RECEIPT")"
    path_rows
    return
  fi
  method="$(receipt_get method)"
  path="$(receipt_get path)"
  row "installed" "$(tilde "$path") $version ($(describe_method "$method" "$(receipt_get source)"))"
  if ! installed_intact; then
    warn_row "modified" "$(tilde "$path") no longer matches what the installer wrote"
  elif [ -z "$newest" ]; then
    :
  elif [ "$newest" = "$version" ] && [ -n "$CHECKOUT" ]; then
    row "current" "$version matches the checkout"
  elif [ "$newest" = "$version" ]; then
    row "current" "$version is the newest release"
  elif [ -n "$CHECKOUT" ]; then
    warn_row "stale" "the checkout is at $newest -- run ./install.sh"
  else
    warn_row "stale" "$newest is out -- run multipass upgrade"
  fi
  path_rows
}

cmd_uninstall() {
  local path
  path="$(receipt_get path)"
  if [ -z "$path" ]; then
    row "not-installed" "no receipt at $(tilde "$RECEIPT")"
  elif [ ! -e "$path" ]; then
    row "missing" "$(tilde "$path") is already gone"
    rm -f "$RECEIPT"
  elif installed_intact; then
    rm -f "$path"
    rm -f "$RECEIPT"
    row "removed" "$(tilde "$path")"
  else
    warn_row "user-owned" "$(tilde "$path") no longer matches what the installer wrote, so it stays"
  fi
  [ -f "$RECEIPT" ] || rmdir "$RECEIPT_DIR" 2>/dev/null || true
  row "kept" "your stores, such as ~/.multipass/store.age"
}

usage() {
  cat <<'EOF_USAGE'
Usage: install.sh [install|status|uninstall]

  install     Install or upgrade multipass (the default)
  status      Say what is installed, and whether it is current
  uninstall   Remove the multipass the installer wrote, keeping your stores

From curl, pass a command after -s --:
  curl -fsSL https://getmultipass.dev/install.sh | bash -s -- status
EOF_USAGE
}

main() {
  check_settings
  case "${1:-install}" in
    install) cmd_install ;;
    status) cmd_status ;;
    uninstall) cmd_uninstall ;;
    -h | --help | help) usage ;;
    *) die "$EX_USAGE" "unknown command $1; use install, status, or uninstall" ;;
  esac
}

main "$@"
